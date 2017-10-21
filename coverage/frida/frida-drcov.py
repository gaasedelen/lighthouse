#!/usr/bin/env python
from __future__ import print_function

"""
A quick and dirty frida-based bb-tracer

If your target is complex, you'll likely want to use a better, dedicated
tracing engine like drcov, or pin. This tracer has some significant
shortcomings, which are exagerated on large, complex binaries:
* It drops coverage, especially near `exit()`
* It cannot easily detect new threads being created, thus cannot instrument
them
* Self modifying code will confuse it, though to be fair I'm not sure how
drcov, pin, or otheres deal with self modifying code either

These shortcomines are probably 10% frida's and 90% the author's. Despite these
flaws however, it is hard to beat the ease of use frida provides.
"""

import argparse
import json
import sys

import frida

js = """
"use strict";

var whitelist = %s;
var threadlist = %s;

// Get the module map
function update_maps() {
    var maps = Process.enumerateModulesSync();
    var i = 0;
    // We need to add the module id
    maps.map(function(o) { o.id = i++; });
    // .. and the module end point
    maps.map(function(o) { o.end = o.base.add(o.size); });

    return maps;
}

function mod_lookup(a) {
    for (var i = 0; i < maps.length; ++i) {
        var m = maps[i];
        if (a.compare(m.base) == 1 && a.compare(m.end) == -1) {
            if (whitelist.indexOf('all') >= 0 ||
                whitelist.indexOf(m.name) >= 0) {
                return {start: m.base, id: m.id};
            } else {
                return {start: 0, id: 0};
            }
        }
    }

    console.log('Could not find module for: ' + a);
    return {start: 0, id: 0};
}

function drcov_bb(bbs, maps) {
    var bb = new ArrayBuffer(8 * bbs.length);

    for (var i = 0; i < bbs.length; ++i) {
        var e = bbs[i];

        var start = e[0];
        var end   = e[1];

        var mod_info = mod_lookup(start);

        if (mod_info.start == 0 && mod_info.id == 0) { continue; }

        var offset = start.sub(mod_info.start).toInt32();
        var size = end.sub(start).toInt32();
        var mod_id = mod_info.id;

        /*
            // Data structure for the coverage info itself
            typedef struct _bb_entry_t {
                uint   start;      // offset of bb start from the image base
                ushort size;
                ushort mod_id;
            } bb_entry_t;
        */

        var x =  new Uint32Array(bb, i * 8, 1);
        x[0] = offset;

        var y = new Uint16Array(bb, i * 8 + 4, 2);
        y[0] = size;
        y[1] = mod_id;
    }

    return bb;
}

var maps = update_maps()
send({'map': maps});

console.log('Starting to stalk threads...');

// Note, we will miss any bbs hit by threads that are created after we've
//  attached
Process.enumerateThreads({
    onMatch: function (thread) {
        if (threadlist.indexOf(thread.id) < 0 && threadlist.indexOf('all') < 0) {
            // This is not the thread you're look for
            return;
        }

        console.log('Stalking thread ' + thread.id);

        Stalker.follow(thread.id, {
            // It would be really nice to use 'compile' here instead of 'block',
            //  but if we did that we'd miss coverage of blocks we hit before
            //  attaching, and I don't really think thats acceptable. It would be
            //  a lot faster though :-/
            events: {
                block: true
            },
            onReceive: function (event) {
                var bb_events = Stalker.parse(event, {stringify: false, annotate: false});
                var bbs = drcov_bb(bb_events, maps);

                // We're going to send a dummy message, the actual bb is in the
                //  data field. We're sending a dict to keep it consistent with the
                //  map. We're also creating the drcov event in javascript, so on
                //  the py recv side we can just blindly add it to a set.
                send({bb:1}, bbs);
            }
        });
    },
    onComplete: function () { console.log('Done stalking threads.'); }
});
"""

modules = []
bbs = set([])

def usage(argv0):
    sys.stderr.write('Usage: %s <process name/pid>\n' % argv0)
    sys.exit(1)

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

    return modules

def populate_bbs(data):
    global bbs

    for i in xrange(0, len(data), 8):
        bbs.add(data[i:i+8])

def create_header(modules):
    header = ''
    header += 'DRCOV VERSION: 2\n'
    header += 'DRCOV FLAVOR: frida\n'
    header += 'Module Table: version 2, count %d\n' % len(modules)
    header += 'Columns: id, base, end, entry, checksum, timestamp, path\n'

    entries = []

    for m in modules:
        # drcov: id, base, end, entry, checksum, timestamp, path
        # frida doesnt give us entry, checksum, or timestamp
        #  luckily, I don't think we need them.
        entry = '%3d, %#016x, %#016x, %#016x, %#08x, %#08x, %s' % (
            m['id'], m['base'], m['end'], 0, 0, 0, m['path'])

        entries.append(entry)

    header_modules = '\n'.join(entries)

    return header + header_modules + '\n'

def create_coverage(data):
    # Filter out the bbs that didnt match, or were unable to resolve
    filtered_bbs = [x for x in bbs if x != '\x00' * 8]

    bb_header = 'BB Table: %d bbs\n' % len(filtered_bbs)
    return bb_header + ''.join(bbs)

def on_message(msg, data):
    #print(msg)
    pay = msg['payload']
    if 'map' in pay:
        maps = msg['payload']['map']
        populate_modules(maps)
    else:
        populate_bbs(data)

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('target', help='target process name or pid')
    parser.add_argument('-o', '--outfile', help='coverage file',
            default='frida-cov.log')
    parser.add_argument('-w', '--whitelist',
            help='module to trace, may be specified multiple times [all]',
            action='append', default=[])
    parser.add_argument('-t', '--thread-id',
            help='threads to trace, may be specified multiple times [all]',
            action='append', type=int, default=[])

    args = parser.parse_args()

    whitelist = args.whitelist if len(args.whitelist) else ['all']
    threadlist = args.thread_id if len(args.thread_id) else ['all']

    json_whitelist = json.dumps(whitelist)
    json_threadlist = json.dumps(threadlist)

    session = frida.attach(args.target)
    script = session.create_script(js % (json_whitelist, json_threadlist))

    script.on('message', on_message)
    script.load()

    print('Got module data, now collecting coverage')
    print('Control-D to terminate....')
    sys.stdin.read()

    print('Detatching...')
    session.detach()

    print('Stopped collecting. Got %d basic blocks.' % len(bbs))
    print('Formatting coverage and saving...')

    header = create_header(modules)
    body = create_coverage(bbs)

    with open(args.outfile, 'wb') as h:
        h.write(header)
        h.write(body)

    print('Done!')

if __name__ == '__main__':
    main(sys.argv)
