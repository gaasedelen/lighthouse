import os
import re
import errno
import struct
import weakref
import datetime
import threading
import collections

from .python import *

BADADDR = 0xFFFFFFFFFFFFFFFF

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
# Theme Util
#------------------------------------------------------------------------------

def swap_rgb(i):
    """
    Swap RRGGBB (integer) to BBGGRR.
    """
    return struct.unpack("<I", struct.pack(">I", i))[0] >> 8

def test_color_brightness(color):
    """
    Test the brightness of a color.
    """
    if color.lightness() > 255.0/2:
        return "light"
    else:
        return "dark"

#------------------------------------------------------------------------------
# Python Util
#------------------------------------------------------------------------------

def makedirs(path, exists_ok=True):
    """
    Make a fully qualified path.
    """
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise e
        if not exists_ok:
            raise e

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

def human_timestamp(timestamp):
    """
    Return a human readable timestamp for a given epoch.
    """
    dt = datetime.datetime.fromtimestamp(timestamp)
    return dt.strftime("%b %d %Y %H:%M:%S")

def get_string_between(text, before, after):
    """
    Get the string between two strings.
    """
    pattern = "%s(.*)%s" % (before, after)
    result = re.search(pattern, text)
    if not result:
        return None
    return result.group(1)

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
        