import os
import gc
import functools

from .misc import is_mainthread

#
# TODO: rewrite shim/compat comments in this file...
#

#------------------------------------------------------------------------------
# Compatability File
#------------------------------------------------------------------------------
#
#    This file is used to reduce the number of compatibility checks made
#    throughout Lighthouse for varying versions of IDA.
#
#    As of July 2017, Lighthouse fully supports IDA 6.8 - 7.0. I expect that
#    much of this compatibility layer and IDA 6.x support will be dropped for
#    maintainability reasons sometime in 2018 as the userbase migrates up to
#    IDA 7.0 and beyond.
#

#------------------------------------------------------------------------------
# Disassembler Platform
#------------------------------------------------------------------------------

class platform(object):
    UNKNOWN = -1
    IDA     = 0
    R2      = 1
    BINJA   = 2
    HOPPER  = 3

# a global holding the disassembler platform type for this execution
active_disassembler = platform.UNKNOWN

# attempt to load IDA imports
if active_disassembler == platform.UNKNOWN:
    try:
        import idaapi
        import idautils
        active_disassembler = platform.IDA
    except ImportError:
        pass

# attempt to load Binary Ninja imports
if active_disassembler == platform.UNKNOWN:
    try:
        import binaryninja
        from binaryninja import PythonScriptingInstance
        from binaryninja.plugin import BackgroundTaskThread
        active_disassembler = platform.BINJA
    except ImportError:
        pass

# throw a hard error on unknown disassembly frameworks
if active_disassembler == platform.UNKNOWN:
    raise RuntimeError("Unknown disassembler! Cannot shim!")

def get_disassembler_platform():
    """
    Return the the disassembler platform this script is executing in.
    """
    return active_disassembler

#------------------------------------------------------------------------------
# Disassembler Build Versioning
#------------------------------------------------------------------------------

# globals holding the disassembler build number
disassembler_version = ""
version_major = 0
version_minor = 0
version_patch = 0

if active_disassembler == platform.IDA:
    disassembler_version = idaapi.get_kernel_version()
    version_major, version_minor = map(int, disassembler_version.split("."))
elif active_disassembler == platform.BINJA:
    disassembler_version = binaryninja.core_version
    version_major, version_minor, version_patch = map(int, disassembler_version.split("."))
else:
    raise RuntimeError("Unknown disassembler! Cannot get version info!")

#------------------------------------------------------------------------------
# IDA 7 API - COMPAT
#------------------------------------------------------------------------------
#
#    In IDA 7.0, Hex-Rays refactored the IDA API quite a bit. This impacts
#    Lighthouse in a few places, so we have had to apply a compatibility
#    fixup to a few places throughout the code.
#
#    We use the 'using_ida7api' global throughout the code to determine if
#    the IDA 7 API is available, and should be used.
#

using_ida7api = active_disassembler == platform.IDA and (version_major > 6)

#------------------------------------------------------------------------------
# PySide --> PyQt5 - COMPAT
#------------------------------------------------------------------------------
#
#    As of IDA 6.9, Hex-Rays has started using PyQt5 versus PySide on Qt4.
#
#    This file tries to help us cut back from having as much compatibility
#    checks/churn by in every other file that consumes them.
#

using_pyqt5 = False

# only specific versions of IDA use PyQt5
if active_disassembler == platform.IDA:
    if using_ida7api:
        using_pyqt5 = True
    elif (version_major == 6 and version_minor >= 9):
        using_pyqt5 = True

# assume all versions of binja use PyQt5
elif active_disassembler == platform.BINJA:
    using_pyqt5 = True

# unknown platform
else:
    raise RuntimeError("Unknown disassembler! Cannot determine Qt support!")

#------------------------------------------------------------------------------
# Synchronization Decorators
#------------------------------------------------------------------------------

def execute_read(function):
    """
    Safe database read decorator, capable of providing return values.

    Modified from https://github.com/vrtadmin/FIRST-plugin-ida
    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        output = [None]

        #
        # this inline function definition is technically what will execute
        # in the context of the main thread. we use this thunk to capture
        # any output the function may want to return to the user.
        #

        def thunk():
            output[0] = function(*args, **kwargs)
            return 1

        #
        # IDA
        #

        if active_disassembler == platform.IDA:
            if is_mainthread():
                thunk()
            else:
                idaapi.execute_sync(thunk, idaapi.MFF_READ)

        #
        # Binary Ninja
        #

        elif active_disassembler == platform.BINJA:

            #
            # It is *only* safe to access the BNDB from a background task,
            # so we must schedule all read/writes this way...
            #

            class DatabaseRead(BackgroundTaskThread):
                """
                A stub task to safely read from the BNDB.
                """
                def __init__(self, text, function):
                    super(DatabaseRead, self).__init__(text, False)
                    self._task_to_run = function
                def run(self):
                    self._task_to_run()
                    self.finish()

            # schedule the read and wait for its completion
            t = DatabaseRead("Reading database...", thunk)
            t.start()
            t.join()

        #
        # unknown
        #

        else:
            raise RuntimeError("Unknown disassembler! Cannot read from database!")

        # return the output of the synchronized execution / read
        return output[0]
    return wrapper

#------------------------------------------------------------------------------
# Binary Ninja Hacks XXX / TODO
#------------------------------------------------------------------------------

def _binja_get_scripting_instance():
    """
    Get the python scripting console in Binary Ninja.
    """
    try:
        python = [o for o in gc.get_objects() if isinstance(o, PythonScriptingInstance.InterpreterThread)][0]
    except IndexError:
        return None
    return python

def binja_get_bv():
    """
    Get the current BinaryView in Binary Ninja.
    """
    python = _binja_get_scripting_instance()
    if not python:
        return None
    return python.current_view

def binja_get_function_at(address):
    """
    Get the function object at the given address.
    """
    bv = binja_get_bv()
    if not bv:
        return None
    return bv.get_function_at(address)

#------------------------------------------------------------------------------
# API Shims
#------------------------------------------------------------------------------

def is_msg_inited():
    """
    Is the disassembler ready to recieve messages to its output window?
    """
    if active_disassembler == platform.IDA:
        return idaapi.is_msg_inited()
    if active_disassembler == platform.BINJA:
        return True
    raise RuntimeError("API not shimmed for the active disassembler")

def get_disassembler_user_directory():
    """
    Return the 'user' directory for the disassembler.
    """
    if active_disassembler == platform.IDA:
        return idaapi.get_user_idadir()
    if active_disassembler == platform.BINJA:
        return os.path.split(binaryninja.user_plugin_path)[0]
    raise RuntimeError("API not shimmed for the active disassembler")

def get_database_directory():
    """
    Return the directory for the current database.
    """
    if active_disassembler == platform.IDA:
        return idautils.GetIdbDir()
    if active_disassembler == platform.BINJA:
        bv = binja_get_bv()
        if not bv:
            return None
        return os.path.dirname(bv.file.filename)
    raise RuntimeError("API not shimmed for the active disassembler")

def get_root_filename():
    """
    Return the root filename used to generate the database.
    """
    if active_disassembler == platform.IDA:
        return idaapi.get_root_filename()

    #
    # TODO: This is the best we can do without getting really ugly.
    #       Binja needs to expose original filename API's ...
    #

    if active_disassembler == platform.BINJA:
        bv = binja_get_bv()
        if not bv:
            return None # TODO: probably need a universal failure code
        return os.path.basename(os.path.splitext(bv.file.filename)[0])

    raise RuntimeError("API not shimmed for the active disassembler")

def get_imagebase():
    """
    Return the base address of the current database.
    """
    if active_disassembler == platform.IDA:
        return idaapi.get_imagebase()
    if active_disassembler == platform.BINJA:
        bv = binja_get_bv()
        if not bv:
            return None # TODO: probably need a universal failure code
        return bv.start
    raise RuntimeError("API not shimmed for the active disassembler")

def get_function_name_at(address):
    """
    Return the name of the function at the given address.
    """
    if active_disassembler == platform.IDA:
        return idaapi.get_short_name(address)
    if active_disassembler == platform.BINJA:
        func = binja_get_function_at(address)
        if not func:
            return None # TODO: probably need a universal failure code
        return func.name
    raise RuntimeError("API not shimmed for the active disassembler")

def navigate(address):
    """
    Jump to the given addreess.
    """
    if active_disassembler == platform.IDA:
        return idaapi.jumpto(address)
    if active_disassembler == platform.BINJA:
        bv = binja_get_bv()
        if not bv:
            return None # TODO: probably need a universal failure code
        return bv.navigate(bv.view, address) # NOTE: BN returns None
    raise RuntimeError("API not shimmed for the active disassembler")

#--------------------------------------------------------------------------
# Event Hooks
#--------------------------------------------------------------------------
#
# TODO: explain...
#

if active_disassembler == platform.IDA:
    if using_ida7api:
        class RenameHooks(idaapi.IDB_Hooks):
            pass
    else:
        class RenameHooks(idaapi.IDP_Hooks):
            pass

# TODO: BINJA DOESN'T HAVE A RENAME EVENT YET...
elif active_disassembler == platform.BINJA:
    class RenameHooks(object):
        def hook(self):
            pass
        def unhook(self):
            pass

else:
    raise RuntimeError("API not shimmed for the active disassembler")

