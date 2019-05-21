#!/usr/bin/env python
from __future__ import print_function

import argparse
import json
import os
import signal
import sys

import frida

"""
Frida BB tracer that outputs in DRcov format.

Frida script is responsible for:
- Getting and sending the process module map initially
- Getting the code execution events
- Parsing the raw event into a GumCompileEvent
- Converting from GumCompileEvent to DRcov block
- Sending a list of DRcov blocks to python

Python side is responsible for:
- Attaching and detaching from the target process
- Removing duplicate DRcov blocks
- Formatting module map and blocks
- Writing the output file
"""

# Our frida script, takes two string arguments to embed
# 1. whitelist of modules, in the form "['module_a', 'module_b']" or "['all']"
# 2. threads to trace, in the form "[345, 765]" or "['all']"
js = """
"use strict";

var whitelist = %s;
var threadlist = %s;

// Get the module map
function make_maps() {
    var maps = Process.enumerateModulesSync();
    var i = 0;
    // We need to add the module id
    maps.map(function(o) { o.id = i++; });
    // .. and the module end point
    maps.map(function(o) { o.end = o.base.add(o.size); });

    return maps;
}

var maps = make_maps()

send({'map': maps});

// We want to use frida's ModuleMap to create DRcov events, however frida's
//  Module object doesn't have the 'id' we added above. To get around this,
//  we'll create a mapping from path -> id, and have the ModuleMap look up the
//  path. While the ModuleMap does contain the base address, if we cache it
//  here, we can simply look up the path rather than the entire Module object.
var module_ids = {};

maps.map(function (e) {
    module_ids[e.path] = {id: e.id, start: e.base};
});

var filtered_maps = new ModuleMap(function (m) {
    if (whitelist.indexOf('all') >= 0) { return true; }

    return whitelist.indexOf(m.name) >= 0;
});

// This function takes a list of GumCompileEvents and converts it into a DRcov
//  entry. Note that we'll get duplicated events when two traced threads
//  execute the same code, but this will be handled by the python side.
function drcov_bbs(bbs, fmaps, path_ids) {
    // We're going to use send(..., data) so we need an array buffer to send
    //  our results back with. Let's go ahead and alloc the max possible
    //  reply size

    /*
        // Data structure for the coverage info itself
        typedef struct _bb_entry_t {
            uint   start;      // offset of bb start from the image base
            ushort size;
            ushort mod_id;
        } bb_entry_t;
    */

    var entry_sz = 8;

    var bb = new ArrayBuffer(entry_sz * bbs.length);

    var num_entries = 0;

    for (var i = 0; i < bbs.length; ++i) {
        var e = bbs[i];

        var start = e[0];
        var end   = e[1];

        var path = fmaps.findPath(start);

        if (path == null) { continue; }

        var mod_info = path_ids[path];

        var offset = start.sub(mod_info.start).toInt32();
        var size = end.sub(start).toInt32();
        var mod_id = mod_info.id;

        // We're going to create two memory views into the array we alloc'd at
        //  the start.

        // we want one u32 after all the other entries we've created
        var x =  new Uint32Array(bb, num_entries * entry_sz, 1);
        x[0] = offset;

        // we want two u16's offset after the 4 byte u32 above
        var y = new Uint16Array(bb, num_entries * entry_sz + 4, 2);
        y[0] = size;
        y[1] = mod_id;

        ++num_entries;
    }

    // We can save some space here, rather than sending the entire array back,
    //  we can create a new view into the already allocated memory, and just
    //  send back that linear chunk.
    return new Uint8Array(bb, 0, num_entries * entry_sz);
}
// Punt on self modifying code -- should improve speed and lighthouse will
//  barf on it anyways
Stalker.trustThreshold = 0;

console.log('Starting to stalk threads...');

// Note, we will miss any bbs hit by threads that are created after we've
//  attached
Process.enumerateThreads({
    onMatch: function (thread) {
        if (threadlist.indexOf(thread.id) < 0 &&
            threadlist.indexOf('all') < 0) {
            // This is not the thread you're look for
            return;
        }

        console.log('Stalking thread ' + thread.id + '.');

        Stalker.follow(thread.id, {
            events: {
                compile: true
            },
            onReceive: function (event) {
                var bb_events = Stalker.parse(event,
                    {stringify: false, annotate: false});
                var bbs = drcov_bbs(bb_events, filtered_maps, module_ids);

                // We're going to send a dummy message, the actual bb is in the
                //  data field. We're sending a dict to keep it consistent with
                //  the map. We're also creating the drcov event in javascript,
                // so on the py recv side we can just blindly add it to a set.
                send({bbs: 1}, bbs);
            }
        });
    },
    onComplete: function () { console.log('Done stalking threads.'); }
});
"""

# These are global so we can easily access them from the frida callbacks or
# signal handlers. It's important that bbs is a set, as we're going to depend
# on it's uniquing behavior for deduplication
modules = []
bbs = set([])
outfile = 'frida-cov.log'

# This converts the object frida sends which has string addresses into
#  a python dict
def populate_modules(image_list):
    global modules

    for image in image_list:
        idx  = image['id']
        path = image['path']
        base = int(image['base'], 0)
        end  = int(image['end'], 0)
        size = image['size']

        m = {
                'id': idx,
                'path': path,
                'base': base,
                'end': end,
                'size': size}

        modules.append(m)

    print('[+] Got module info.')

# called when we get coverage data from frida
def populate_bbs(data):
    global bbs

    # we know every drcov block is 8 bytes, so lets just blindly slice and
    #  insert. This will dedup for us.
    block_sz = 8
    for i in range(0, len(data), block_sz):
        bbs.add(data[i:i+block_sz])

# take the module dict and format it as a drcov logfile header
def create_header(mods):
    header = ''
    header += 'DRCOV VERSION: 2\n'
    header += 'DRCOV FLAVOR: frida\n'
    header += 'Module Table: version 2, count %d\n' % len(mods)
    header += 'Columns: id, base, end, entry, checksum, timestamp, path\n'

    entries = []

    for m in mods:
        # drcov: id, base, end, entry, checksum, timestamp, path
        # frida doesnt give us entry, checksum, or timestamp
        #  luckily, I don't think we need them.
        entry = '%3d, %#016x, %#016x, %#016x, %#08x, %#08x, %s' % (
            m['id'], m['base'], m['end'], 0, 0, 0, m['path'])

        entries.append(entry)

    header_modules = '\n'.join(entries)

    return header + header_modules + '\n'

# take the recv'd basic blocks, finish the header, and append the coverage
def create_coverage(data):
    bb_header = 'BB Table: %d bbs\n' % len(data)
    return bb_header + ''.join(data)

def on_message(msg, data):
    #print(msg)
    pay = msg['payload']
    if 'map' in pay:
        maps = pay['map']
        populate_modules(maps)
    else:
        populate_bbs(data)

def sigint(signo, frame):
    print('[!] SIGINT, saving %d blocks to \'%s\'' % (len(bbs), outfile))

    save_coverage()

    print('[!] Done')

    os._exit(1)

def save_coverage():
    header = create_header(modules)
    body = create_coverage(bbs)

    with open(outfile, 'wb') as h:
        h.write(header)
        h.write(body)

def main():
    global outfile

    parser = argparse.ArgumentParser()
    parser.add_argument('target',
            help='target process name or pid',
            default='-1')
    parser.add_argument('-o', '--outfile',
            help='coverage file',
            default='frida-cov.log')
    parser.add_argument('-w', '--whitelist-modules',
            help='module to trace, may be specified multiple times [all]',
            action='append', default=[])
    parser.add_argument('-t', '--thread-id',
            help='threads to trace, may be specified multiple times [all]',
            action='append', type=int, default=[])
    parser.add_argument('-D', '--device',
            help='select a device by id [local]',
            default='local')

    args = parser.parse_args()

    outfile = args.outfile

    device = frida.get_device(args.device)

    target = -1
    for p in device.enumerate_processes():
        if args.target in [str(p.pid), p.name]:
            if target == -1:
                target = p.pid
            else:
                print('[-] Warning: multiple processes on device match '
                      '\'%s\', using pid: %d' % (args.target, target))

    if target == -1:
        print('[-] Error: could not find process matching '
              '\'%s\' on device \'%s\'' % (args.target, device.id))
        sys.exit(1)

    signal.signal(signal.SIGINT, sigint)

    whitelist_modules = ['all']
    if len(args.whitelist_modules):
            whitelist_modules = args.whitelist_modules

    threadlist = ['all']
    if len(args.thread_id):
        threadlist = args.thread_id

    json_whitelist_modules = json.dumps(whitelist_modules)
    json_threadlist = json.dumps(threadlist)

    print('[*] Attaching to pid \'%d\' on device \'%s\'...' %
            (target, device.id))

    session = device.attach(target)
    print('[+] Attached. Loading script...')

    script = session.create_script(js % (json_whitelist_modules, json_threadlist))
    script.on('message', on_message)
    script.load()

    print('[*] Now collecting info, control-D to terminate....')

    sys.stdin.read()

    print('[*] Detaching, this might take a second...')
    session.detach()

    print('[+] Detached. Got %d basic blocks.' % len(bbs))
    print('[*] Formatting coverage and saving...')

    save_coverage()

    print('[!] Done')

    sys.exit(0)

if __name__ == '__main__':
    main()
