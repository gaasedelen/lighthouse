# -*- coding: utf-8 -*-
import os
import sys
import logging
import functools
import threading

import binaryninja
from binaryninja import PythonScriptingInstance, binaryview
from binaryninjaui import DockHandler, DockContextHandler, UIContext, UIActionHandler
from binaryninja.plugin import BackgroundTaskThread

from .api import DisassemblerCoreAPI, DisassemblerContextAPI
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

class BinjaCoreAPI(DisassemblerCoreAPI):
    """
    The Binary Ninja implementation of the disassembler API abstraction.
    """
    NAME = "BINJA"

    def __init__(self):
        super(BinjaCoreAPI, self).__init__()
        self._init_version()

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
    def headless(self):
        ret = None
        # Compatibility for Binary Ninja Stable & Dev channels (Jan 2019)
        try:
            ret = binaryninja.core_ui_enabled()
        except TypeError:
            ret = binaryninja.core_ui_enabled
        return not ret

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
            binaryninja.execute_on_main_thread(ff)

        return wrapper

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    def get_disassembler_user_directory(self):
        return os.path.split(binaryninja.user_plugin_path())[0]

    def get_disassembly_background_color(self):
        palette = QtGui.QPalette()
        return palette.color(QtGui.QPalette.Button)

    def is_msg_inited(self):
        return True

    def warning(self, text):
        binaryninja.interaction.show_message_box("Warning", text)

    def message(self, message):
        print(message)

    #--------------------------------------------------------------------------
    # UI API Shims
    #--------------------------------------------------------------------------

    def create_dockable_widget(self, dockable_name, create_widget_callback):
        dock_handler = DockHandler.getActiveDockHandler()
        dock_handler.addDockWidget(dockable_name, create_widget_callback, QtCore.Qt.RightDockWidgetArea, QtCore.Qt.Horizontal, False)

    def show_dockable_widget(self, dockable_name):
        dock_handler = DockHandler.getActiveDockHandler()
        dock_handler.setVisible(dockable_name, True)

    #--------------------------------------------------------------------------
    # XXX Binja Specfic Helpers
    #--------------------------------------------------------------------------

    def binja_get_bv_from_dock(self):
        dh = DockHandler.getActiveDockHandler()
        if not dh:
            return None
        vf = dh.getViewFrame()
        if not vf:
            return None
        vi = vf.getCurrentViewInterface()
        bv = vi.getData()
        return bv

class BinjaContextAPI(DisassemblerContextAPI):
    """
    TODO
    """

    def __init__(self, dctx):
        super(BinjaContextAPI, self).__init__(dctx)
        self.bv = dctx

    @property
    def busy(self):
        return self.bv.analysis_info.state != binaryninja.enums.AnalysisState.IdleState

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

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    def get_current_address(self):
        raise NotImplementedError("TODO!")
        return 0

    @BinjaCoreAPI.execute_read
    def get_database_directory(self):
        return os.path.dirname(self.bv.file.filename)

    @not_mainthread
    def get_function_addresses(self):
        return [x.start for x in self.bv.functions]

    def get_function_name_at(self, address):
        func = self.bv.get_function_at(address)
        if not func:
            return None
        return func.symbol.short_name

    @BinjaCoreAPI.execute_read
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

    @BinjaCoreAPI.execute_write
    def set_function_name_at(self, function_address, new_name):
        func = self.bv.get_function_at(function_address)
        if not func:
            return
        if new_name == "":
            new_name = None
        func.name = new_name

    #--------------------------------------------------------------------------
    # Hooks API
    #--------------------------------------------------------------------------

    def create_rename_hooks(self):
        return RenameHooks(self.bv)

    #------------------------------------------------------------------------------
    # Function Prefix API
    #------------------------------------------------------------------------------

    PREFIX_SEPARATOR = "▁" # Unicode 0x2581

#------------------------------------------------------------------------------
# Hooking
#------------------------------------------------------------------------------

class RenameHooks(binaryview.BinaryDataNotification):
    """
    A hooking class to catch symbol changes in Binary Ninja.
    """

    def __init__(self, bv):
        self._bv = bv
        self.symbol_added = self.__symbol_handler
        self.symbol_updated = self.__symbol_handler
        self.symbol_removed = self.__symbol_handler

    def hook(self):
        self._bv.register_notification(self)

    def unhook(self):
        self._bv.unregister_notification(self)

    def __symbol_handler(self, view, symbol):
        func = self._bv.get_function_at(symbol.address)
        if not func.start == symbol.address:
            return
        self.renamed(symbol.address, symbol.name)

#------------------------------------------------------------------------------
# UI
#------------------------------------------------------------------------------

class DockableChild(QtWidgets.QWidget, DockContextHandler):
    """
    A dockable Qt widget for Binary Ninja.
    """

    def __init__(self, parent, name, dctx=None):

        QtWidgets.QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.name = name
        self.dctx = dctx

        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        self.visible = False

        #self._widget.setSizePolicy(
        #    QtWidgets.QSizePolicy.Expanding,
        #    QtWidgets.QSizePolicy.Expanding
        #)

        ## dock the widget on the right side of Binja
        #self._dock_handler.addDockWidget(self._widget, QtCore.Qt.RightDockWidgetArea, QtCore.Qt.Horizontal, True, False)
        #self._dockable = self._dock_handler.getDockWidget(self._window_title)

        #self._dockable = QtWidgets.QDockWidget(window_title, self._main_window)
        #self._dockable.setWindowIcon(self._window_icon)
        #self._dockable.setSizePolicy(
        #    QtWidgets.QSizePolicy.Expanding,
        #    QtWidgets.QSizePolicy.Expanding
        #)

    def notifyOffsetChanged(self, offset):
        #print("Offset changed..")
        #self.offset.setText(hex(offset))
        pass

    def shouldBeVisible(self, view_frame):
        print("Should be visible called...")
        if view_frame is None:
            print(" - No, there's no BV")
            return False
        print("%r" % self.visible)
        return self.visible

    def notifyVisibilityChanged(self, is_visible):
        print("Vis changed...")
        self.visible = is_visible

    def notifyViewChanged(self, view_frame):
        print("Notify view changed", view_frame)
        return
        if view_frame is None:
            self.datatype.setText("None")
            self.data = None
        else:
            self.datatype.setText(view_frame.getCurrentView())
            view = view_frame.getCurrentViewInterface()
            self.data = view.getData()

    def contextMenuEvent(self, event):
        print("CTX Menu event")
        return
        #self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

