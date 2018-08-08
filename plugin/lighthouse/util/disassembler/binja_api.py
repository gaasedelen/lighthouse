import os
import logging
import functools
import threading

from .api import DisassemblerAPI
from lighthouse.util.misc import is_mainthread

import binaryninja
from binaryninja import PythonScriptingInstance, binaryview
from binaryninja.plugin import BackgroundTaskThread

logger = logging.getLogger("Lighthouse.API.Binja")

class BinjaAPI(DisassemblerAPI):
    """
    TODO/COMMENT
    """
    NAME = "BINJA"

    def __init__(self, bv=None):
        self._bv = bv
        self._python = _binja_get_scripting_instance()
        self._init_version()

    def _init_version(self):

        # retrieve Binja's version #
        disassembler_version = binaryninja.core_version.split("-", 1)[0]
        major, minor, patch = map(int, disassembler_version.split("."))

        # save the version number components for later use
        self._version_major = major
        self._version_minor = minor
        self._version_patch = patch

    #------------------------------------------------------------------------------
    # Properties
    #------------------------------------------------------------------------------

    @property
    def bv(self):
        return self._bv

    @bv.setter
    def bv(self, bv):
        if self._bv == bv:
            return
        if self._bv:
            raise ValueError("BinaryView cannot be changed once set...")
        self._bv = bv

    @property
    def version_major(self):
        return self._version_major

    @property
    def version_minor(self):
        return self._version_minor

    @property
    def version_patch(self):
        return self._version_patch

    #------------------------------------------------------------------------------
    # API Shims
    #------------------------------------------------------------------------------

    def create_rename_hooks(self):
        return RenameHooks(self.bv)

    def get_current_address(self):
        if not self._python:
            self._python = _binja_get_scripting_instance()
            if not self._python:
                return -1
        return self._python.current_addr

    def get_database_directory(self):
        return os.path.dirname(self.bv.file.filename)

    def get_disassembler_user_directory(self):
        return os.path.split(binaryninja.user_plugin_path)[0]

    def get_function_addresses(self):
        return [x.start for x in self.bv.functions]

    def get_function_name_at(self, address):
        func = self.bv.get_function_at(address)
        if not func:
            return None
        return func.name

    def get_imagebase(self):
        return self.bv.start

    def get_root_filename(self):
        """
        TODO/V35: Binja needs to expose original filename API's ...

        This is the best we can do without getting really ugly.
        """
        return os.path.basename(os.path.splitext(self.bv.file.filename)[0])

    def is_msg_inited(self):
        return True

    def navigate(self, address):
        return self.bv.navigate(self.bv.view, address) # NOTE: BN returns None

    @staticmethod
    def execute_read(function):

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

            # return the output of the synchronized execution / read
            return output[0]
        return wrapper

    @staticmethod
    def execute_ui(function):
        """
        Decorator to execute a function in the disassembler main thread.

        This is generally used for scheduling UI (Qt) events originating from
        a background thread.

        NOTE: Using this decorator waives your right to a return value.
        """

        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            ff = functools.partial(function, *args, **kwargs)

            # if we are already in the main (UI) thread, execute now
            if is_mainthread():
                ff()

            # schedule the task to run in the main thread
            try:
                binaryninja.execute_on_main_thread(ff)
            except AttributeError: # TODO/V35: binja bug, reported on 5/31/2018
                pass

        return wrapper

#------------------------------------------------------------------------------
# Hooking
#------------------------------------------------------------------------------

class RenameHooks(object):
    """
    TODO/COMMENT
    """

    def __init__(self, bv):
        self._bv = bv

        # hook certain Binary Ninja notifications
        self._hooks = binaryview.BinaryDataNotification()
        self._hooks.function_updated = self._workaround

        # TODO/V35: turns out there are no adequate symbol event hooks...
        #self._hooks.function_update_requested = self._before
        #self._hooks.function_updated = self._after
        #self._names = {}

    def hook(self):
        self._bv.register_notification(self._hooks)

    def unhook(self):
        self._bv.unregister_notification(self._hooks)

    @BinjaAPI.execute_ui
    def _renamed(self, address, new_name):
        """
        Pass off the (internal) rename event to the mainthread.
        """
        self.renamed(address, new_name)

    def _before(self, _, function):
        """
        Capture function name prior to modification.
        """
        self._names[function.start] = function.name

    def _after(self, _, function):
        """
        Capture function name post modification
        """

        #
        # if we don't have an old name for a given function logged, that
        # means we must have missed the function_update_requested event for it.
        #
        # hopefully this should never happen during real *rename* events...
        #

        old_name = self._names.get(function.start, None)
        if not old_name:
            return

        # if the function name hasn't changed, then there is nothing to do!
        if old_name == function.name:
            return

        # fire our custom 'function renamed' event
        self._renamed(function.start, function.name)

    #--------------------------------------------------------------------------
    # Temporary Workaound
    #--------------------------------------------------------------------------

    def _workaround(self, _, function):
        """
        TODO/V35: workaround to detect name changes pending better API's
        """
        function_metadata = self.metadata.get_function(function.start)
        if not function_metadata:
            return

        # if the function name hasn't changed, then there is nothing to do!
        if function_metadata.name == function.name:
            return

        print "NAME CHANGED! %s --> %s" % (function_metadata.name, function.name)
        # fire our custom 'function renamed' event
        self._renamed(function.start, function.name)

#------------------------------------------------------------------------------
# Binary Ninja Hacks XXX / TODO
#------------------------------------------------------------------------------

def _binja_get_scripting_instance():
    """
    Get the python scripting console in Binary Ninja.
    """
    for t in threading.enumerate():
        if type(t) == PythonScriptingInstance.InterpreterThread:
            return t
    return None

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
