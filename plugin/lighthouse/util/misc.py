import os
import weakref
import threading
import collections

#------------------------------------------------------------------------------
# Plugin Util
#------------------------------------------------------------------------------

PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def plugin_resource(resource_name):
    """
    Return the full path for a given plugin resource file.
    """
    return os.path.join(
        PLUGIN_PATH,
        "ui",
        "resources",
        resource_name
    )

#------------------------------------------------------------------------------
# Thread Util
#------------------------------------------------------------------------------

def is_mainthread():
    """
    Return a bool that indicates if this is the main application thread.
    """
    return isinstance(threading.current_thread(), threading._MainThread)

def mainthread(f):
    """
    A debug decorator to ensure that a function is always called from the main thread.
    """
    def wrapper(*args, **kwargs):
        assert is_mainthread()
        return f(*args, **kwargs)
    return wrapper

def not_mainthread(f):
    """
    A debug decorator to ensure that a function is never called from the main thread.
    """
    def wrapper(*args, **kwargs):
        assert not is_mainthread()
        return f(*args, **kwargs)
    return wrapper

#------------------------------------------------------------------------------
# Python Util
#------------------------------------------------------------------------------

def chunks(l, n):
    """
    Yield successive n-sized chunks from a list (l).

    From http://stackoverflow.com/a/312464
    """
    for i in xrange(0, len(l), n):
        yield l[i:i + n]

def hex_list(items):
    """
    Return a string of a python-like list, with hex numbers.

    [0, 5420, 1942512] --> '[0x0, 0x152C, 0x1DA30]'
    """
    return '[{}]'.format(', '.join('0x%X' % x for x in items))

#------------------------------------------------------------------------------
# Python Callback / Signals
#------------------------------------------------------------------------------

def register_callback(callback_list, callback):
    """
    Register a callable function to the given callback_list.

    Adapted from http://stackoverflow.com/a/21941670
    """

    # create a weakref callback to an object method
    try:
        callback_ref = weakref.ref(callback.__func__), weakref.ref(callback.__self__)

    # create a wweakref callback to a stand alone function
    except AttributeError:
        callback_ref = weakref.ref(callback), None

    # 'register' the callback
    callback_list.append(callback_ref)

def notify_callback(callback_list, *args):
    """
    Notify the given list of registered callbacks of an event.

    The given list (callback_list) is a list of weakref'd callables
    registered through the register_callback() function. To notify the
    callbacks of an event, this function will simply loop through the list
    and call them.

    This routine self-heals by removing dead callbacks for deleted objects as
    it encounters them.

    Adapted from http://stackoverflow.com/a/21941670
    """
    cleanup = []

    #
    # loop through all the registered callbacks in the given callback_list,
    # notifying active callbacks, and removing dead ones.
    #

    for callback_ref in callback_list:
        callback, obj_ref = callback_ref[0](), callback_ref[1]

        #
        # if the callback is an instance method, deference the instance
        # (an object) first to check that it is still alive
        #

        if obj_ref:
            obj = obj_ref()

            # if the object instance is gone, mark this callback for cleanup
            if obj is None:
                cleanup.append(callback_ref)
                continue

            # call the object instance callback
            try:
                callback(obj, *args)

            # assume a Qt cleanup/deletion occurred
            except RuntimeError as e:
                cleanup.append(callback_ref)
                continue

        # if the callback is a static method...
        else:

            # if the static method is deleted, mark this callback for cleanup
            if callback is None:
                cleanup.append(callback_ref)
                continue

            # call the static callback
            callback(*args)

    # remove the deleted callbacks
    for callback_ref in cleanup:
        callback_list.remove(callback_ref)

#------------------------------------------------------------------------------
# Coverage Util
#------------------------------------------------------------------------------

def coalesce_blocks(blocks):
    """
    Coalesce a list of (address, size) blocks.

    eg:
        blocks = [
            (4100, 10),
            (4200, 100),
            (4300, 10),
            (4310, 20),
            (4400, 10),
        ]

    returns:
        coalesced = [(4100, 10), (4200, 130), (4400, 10)]

    """

    # nothing to do
    if not blocks:
        return []
    elif len(blocks) == 1:
        return blocks

    # before we can operate on the blocks, we must ensure they are sorted
    blocks = sorted(blocks)

    #
    # coalesce the list of given blocks
    #

    coalesced = [blocks.pop(0)]
    while blocks:

        block_start, block_size = blocks.pop(0)

        #
        # compute the end address of the current coalescing block. if the
        # blocks do not overlap, create a new block to start coalescing from
        #

        if sum(coalesced[-1]) < block_start:
            coalesced.append((block_start, block_size))
            continue

        #
        # the blocks overlap, so update the current coalescing block
        #

        coalesced[-1] = (coalesced[-1][0], (block_start+block_size) - coalesced[-1][0])

    # return the list of coalesced blocks
    return coalesced

def rebase_blocks(base, basic_blocks):
    """
    Rebase a list of basic block offsets (offset, size) to the given imagebase.
    """
    return map(lambda x: (base + x[0], x[1]), basic_blocks)

def build_hitmap(data):
    """
    Build a hitmap from the given list of address.

    A hitmap is a map of address --> number of executions.

    The list of input addresses can be any sort of runtime trace, coverage,
    or profiling data that one would like to build a hitmap for.
    """
    output = collections.defaultdict(int)

    # if there is no input data, simply return an empty hitmap
    if not data:
        return output

    #
    # walk through the given list of given addresses and build a
    # corresponding hitmap for them
    #

    for address in data:
        output[address] += 1

    # return the hitmap
    return output
