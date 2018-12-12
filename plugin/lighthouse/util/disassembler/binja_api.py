# -*- coding: utf-8 -*-
import os
import sys
import logging
import functools
import threading

import binaryninja
from binaryninja import PythonScriptingInstance, binaryview
from binaryninja.plugin import BackgroundTaskThread

#------------------------------------------------------------------------------
# External PyQt5 Dependency
#------------------------------------------------------------------------------
#
#    amend the Python import path with a Libs folder for additional pip
#    packages required by Lighthouse (at least on Windows, and maybe macOS)
#
#    TODO/FUTURE: it is kind of dirty that we have to do this here. maybe it
#    can be moved with a later refactor. in the long run, binary ninja will
#    ship with PyQt5 bindings in-box.
#

DEPENDENCY_PATH = os.path.join(
    binaryninja.user_plugin_path(),
    "Lib",
    "site-packages"
)
sys.path.append(DEPENDENCY_PATH)

#------------------------------------------------------------------------------

from .api import DisassemblerAPI, DockableShim
from ..qt import *
from ..misc import is_mainthread, not_mainthread

logger = logging.getLogger("Lighthouse.API.Binja")

#------------------------------------------------------------------------------
# Utils
#------------------------------------------------------------------------------

def execute_sync(function):
    """
    Synchronize with the disassembler for safe database access.
    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):

        #
        # in Binary Ninja, it is only safe to access the BNDB from a thread
        # that is *not* the mainthread. if we appear to already be in a
        # background thread of some sort, simply execute the given function
        #

        if not is_mainthread():
            return function(*args, **kwargs)

        #
        # if we are in the mainthread, we need to schedule a background
        # task to perform our database task/function instead
        #
        # this inline function definition is technically what will execute
        # in a database-safe background thread. we use this thunk to
        # capture any output the function may want to return to the user.
        #

        output = [None]
        def thunk():
            output[0] = function(*args, **kwargs)
            return 1

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

        # schedule the databases read and wait for its completion
        t = DatabaseRead("Accessing database...", thunk)
        t.start()
        t.join()

        # return the output of the synchronized execution / read
        return output[0]
    return wrapper

#------------------------------------------------------------------------------
# Disassembler API
#------------------------------------------------------------------------------

class BinjaAPI(DisassemblerAPI):
    """
    The Binary Ninja implementation of the disassembler API abstraction.
    """
    NAME = "BINJA"

    def __init__(self, bv=None):
        super(BinjaAPI, self).__init__()
        self._init_version()

        # binja specific amenities
        self._bv = bv
        self._python = _binja_get_scripting_instance()

    def _init_version(self):
        version_string = binaryninja.core_version()

        # retrieve Binja's version #
        if "-" in version_string: # dev
            disassembler_version = version_string.split("-", 1)[0]
        else: # commercial, personal
            disassembler_version = version_string.split(" ", 1)[0]

        major, minor, patch = map(int, disassembler_version.split("."))

        # save the version number components for later use
        self._version_major = major
        self._version_minor = minor
        self._version_patch = patch

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

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

    @property
    def headless(self):
        return not binaryninja.core_ui_enabled()

    #--------------------------------------------------------------------------
    # Synchronization Decorators
    #--------------------------------------------------------------------------

    @staticmethod
    def execute_read(function):
        return execute_sync(function)

    @staticmethod
    def execute_write(function):
        return execute_sync(function)

    @staticmethod
    def execute_ui(function):

        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            ff = functools.partial(function, *args, **kwargs)

            # if we are already in the main (UI) thread, execute now
            if is_mainthread():
                ff()
                return

            # schedule the task to run in the main thread
            try:
                binaryninja.execute_on_main_thread(ff)
            except AttributeError: # TODO/V35: binja bug, fixed on dev
                pass

        return wrapper

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    #
    #  NOTE/TODO/V35:
    #
    #    The use of @not_mainthread or @execute_read on some of these API's
    #    is to ensure the function is called from a background thread/task.
    #    This is because calling database functions from the mainthread can
    #    cause deadlocks (not threadsafe?) in Binary Ninja...
    #
    #    this is pretty annoying because it conflicts directly with IDA
    #    which *needs* database accesses to be made from the mainthread
    #

    def create_rename_hooks(self):
        return RenameHooks(self.bv)

    def get_current_address(self):
        if not self._python:
            self._python = _binja_get_scripting_instance()
            if not self._python:
                return -1
        return self._python.current_addr

    @execute_read.__func__
    def get_database_directory(self):
        return os.path.dirname(self.bv.file.filename)

    def get_disassembler_user_directory(self):
        return os.path.split(binaryninja.user_plugin_path())[0]

    @not_mainthread
    def get_function_addresses(self):
        return [x.start for x in self.bv.functions]

    @not_mainthread
    def get_function_name_at(self, address):
        func = self.bv.get_function_at(address)
        if not func:
            return None
        return func.symbol.short_name

    @execute_read.__func__
    def get_function_raw_name_at(self, address):
        func = self.bv.get_function_at(address)
        if not func:
            return None
        return func.name

    @not_mainthread
    def get_imagebase(self):
        return self.bv.start

    @not_mainthread
    def get_root_filename(self):
        return os.path.basename(self.bv.file.original_filename)

    def navigate(self, address):
        return self.bv.navigate(self.bv.view, address)

    @execute_write.__func__
    def set_function_name_at(self, function_address, new_name):
        func = self.bv.get_function_at(function_address)
        if not func:
            return
        if new_name == "":
            new_name = None
        func.name = new_name

        #
        # TODO/V35: As a workaround for no symbol events, we trigger a data
        # notification for this function instead.
        #

        self.bv.write(function_address, self.bv.read(function_address, 1))

    #--------------------------------------------------------------------------
    # UI API Shims
    #--------------------------------------------------------------------------

    def get_disassembly_background_color(self):
        palette = QtGui.QPalette()
        return palette.color(QtGui.QPalette.Button)

    def is_msg_inited(self):
        return True

    def warning(self, text):
        binaryninja.interaction.show_message_box("Warning", text)

    #------------------------------------------------------------------------------
    # Function Prefix API
    #------------------------------------------------------------------------------

    PREFIX_SEPARATOR = "▁" # Unicode 0x2581

#------------------------------------------------------------------------------
# Hooking
#------------------------------------------------------------------------------

class RenameHooks(object):
    """
    A Hooking class to catch function renames in Binary Ninja.
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
        if function_metadata.name == function.symbol.short_name:
            return

        # fire our custom 'function renamed' event
        self._renamed(function.start, function.symbol.short_name)

#------------------------------------------------------------------------------
# UI
#------------------------------------------------------------------------------

class DockableWindow(DockableShim):
    """
    A dockable Qt widget for Binary Ninja.
    """

    def __init__(self, window_title, icon_path):
        super(DockableWindow, self).__init__(window_title, icon_path)

        # configure dockable widget container
        self._main_window = get_qt_main_window()
        self._widget = QtWidgets.QWidget()
        self._dockable = QtWidgets.QDockWidget(window_title, self._main_window)
        self._dockable.setWidget(self._widget)
        self._dockable.setWindowIcon(self._window_icon)
        self._dockable.setAttribute(QtCore.Qt.WA_DeleteOnClose)
        self._dockable.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding,
            QtWidgets.QSizePolicy.Expanding
        )
        self._widget.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding,
            QtWidgets.QSizePolicy.Expanding
        )

        # dock the widget on the right side of Binja
        self._main_window.addDockWidget(
            QtCore.Qt.RightDockWidgetArea,
            self._dockable
        )

    def show(self):

        #
        # NOTE/HACK:
        #   this is a little dirty, but is used to set the default width
        #   of the coverage overview / dockable widget when it is first shown
        #

        default_width = self._widget.sizeHint().width()
        self._dockable.setMinimumWidth(default_width)

        # show the widget
        self._dockable.show()

        # undo the HACK
        self._dockable.setMinimumWidth(0)

#------------------------------------------------------------------------------
# Binary Ninja Hacks XXX / TODO / V35
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
