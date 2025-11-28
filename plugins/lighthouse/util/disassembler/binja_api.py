import ctypes
import collections
import functools
import logging
import os
import sys
import threading

from binaryninja import PythonScriptingInstance, binaryview
from binaryninja.plugin import BackgroundTaskThread
from binaryninjaui import (Sidebar, SidebarContextSensitivity, SidebarWidget,
                           SidebarWidgetLocation, SidebarWidgetType,
                           UIActionHandler, UIContext)
from PySide6 import QtCore
from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QImage, QPainter, QPixmap

from ..misc import is_mainthread, not_mainthread
from ..qt import *
from .api import DisassemblerContextAPI, DisassemblerCoreAPI

logger = logging.getLogger("Lighthouse.API.Binja")

# ------------------------------------------------------------------------------
# Utils
# ------------------------------------------------------------------------------


def execute_sync(function):
    # 

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


# ------------------------------------------------------------------------------
# Disassembler API
# ------------------------------------------------------------------------------


class BinjaCoreAPI(DisassemblerCoreAPI):
    NAME = "BINJA"

    def __init__(self):
        super(BinjaCoreAPI, self).__init__()
        self._init_version()
        # Store a reference to the SidebarWidgetType instance
        self._sidebar_widget_type = None

    def _init_version(self):
        version_string = binaryninja.core_version()

        # retrieve Binja's version #
        if "-" in version_string:  # dev
            disassembler_version = version_string.split("-", 1)[0]
        else:  # commercial, personal
            disassembler_version = version_string.split(" ", 1)[0]

        major, minor, patch, *_ = disassembler_version.split(".") + ["0"]

        # save the version number components for later use
        self._version_major = major
        self._version_minor = minor
        self._version_patch = patch

    # --------------------------------------------------------------------------
    # Properties
    # --------------------------------------------------------------------------

    @property
    def headless(self):
        return not (binaryninja.core_ui_enabled())

    # --------------------------------------------------------------------------
    # Synchronization Decorators
    # --------------------------------------------------------------------------

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

    # --------------------------------------------------------------------------
    # API Shims
    # --------------------------------------------------------------------------

    def get_disassembler_user_directory(self):
        return os.path.split(binaryninja.user_plugin_path())[0]

    def get_disassembly_background_color(self):
        return binaryninjaui.getThemeColor(
            binaryninjaui.ThemeColor.LinearDisassemblyBlockColor
        )

    def is_msg_inited(self):
        return True

    @execute_ui.__func__
    def warning(self, text):
        super(BinjaCoreAPI, self).warning(text)

    def message(self, message):
        print(message)

    # --------------------------------------------------------------------------
    # UI API Shims (Migrated to SidebarWidget)
    # --------------------------------------------------------------------------

    def register_dockable(self, dockable_name, create_widget_callback):
        # We store the SidebarWidgetType instance so we don't re-register it
        if self._sidebar_widget_type is None:
            self._sidebar_widget_type = LighthouseWidgetType()
            Sidebar.addSidebarWidgetType(self._sidebar_widget_type)

    def create_dockable_widget(self, parent, dockable_name):
        # This method is now implicitly handled by LighthouseWidgetType.createWidget
        pass

    def show_dockable(self, dockable_name):
        """
        Show the named dockable widget.
        """
        current_sidebar = Sidebar.current()
        
        if current_sidebar:
            # FIX: Use the registered plugin name "Lighthouse"
            current_sidebar.focus("Lighthouse")
        else:
            # Fallback for when no sidebar/frame is currently active/focused
            self.warning("Failed to show dockable '%s': No active BinaryView window with a sidebar found." % dockable_name)

    def hide_dockable(self, dockable_name):
        pass

    # --------------------------------------------------------------------------
    # XXX Binja Specfic Helpers
    # --------------------------------------------------------------------------

    def binja_get_bv_from_dock(self):
        ac = UIContext.activeContext()
        if not ac:
            return None
        vf = ac.getCurrentViewFrame()
        if not vf:
            return None
        vi = vf.getCurrentViewInterface()
        bv = vi.getData()
        return bv


class BinjaContextAPI(DisassemblerContextAPI):

    def __init__(self, dctx):
        super(BinjaContextAPI, self).__init__(dctx)
        self.bv = dctx

    # --------------------------------------------------------------------------
    # Properties
    # --------------------------------------------------------------------------

    @property
    def busy(self):
        return self.bv.analysis_info.state != binaryninja.enums.AnalysisState.IdleState

    # --------------------------------------------------------------------------
    # API Shims
    # --------------------------------------------------------------------------

    def get_current_address(self):
        ac = UIContext.activeContext()
        if not ac:
            return 0
        vf = ac.getCurrentViewFrame()
        if not vf:
            return 0
        actx = vf.actionContext()
        if not actx:
            return 0
        return actx.address

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

    def navigate_to_function(self, function_address, address):

        #
        # attempt a more 'precise' jump, that guarantees to place us within
        # the given function. this is necessary when trying to jump to an
        # an address/node that is shared between two functions
        #

        funcs = self.bv.get_functions_containing(address)
        if not funcs:
            return False

        #
        # try to find the function that contains our target (address) and has
        # a matching function start...
        #

        for func in funcs:
            if func.start == function_address:
                break

        # no matching function ???
        else:
            return False

        ac = UIContext.activeContext()
        vf = ac.getCurrentViewFrame()
        vi = vf.getCurrentViewInterface()

        return vi.navigateToFunction(func, address)

    def set_function_name_at(self, function_address, new_name):
        func = self.bv.get_function_at(function_address)

        if not func:
            return

        if new_name == "":
            new_name = None

        state = self.bv.begin_undo_actions()
        func.name = new_name
        self.bv.commit_undo_actions(state)

    # --------------------------------------------------------------------------
    # Hooks API
    # --------------------------------------------------------------------------

    def create_rename_hooks(self):
        return RenameHooks(self.bv)

    # ------------------------------------------------------------------------------
    # Function Prefix API
    # ------------------------------------------------------------------------------

    PREFIX_SEPARATOR = " "  # Unicode 0x2581


# ------------------------------------------------------------------------------
# Hooking
# ------------------------------------------------------------------------------


class RenameHooks(binaryview.BinaryDataNotification):
    """
    A hooking class to catch symbol changes in Binary Ninja.
    """

    def __init__(self, bv):
        self._bv = bv

    def hook(self):
        self._bv.register_notification(self)

    def unhook(self):
        self._bv.unregister_notification(self)

    def symbol_added(self, *args):
        self.__symbol_handler(*args)

    def symbol_updated(self, *args):
        self.__symbol_handler(*args)

    def symbol_removed(self, *args):
        self.__symbol_handler(*args, True)

    def __symbol_handler(self, view, symbol, removed=False):

        func = self._bv.get_function_at(symbol.address)
        if not func or not func.start == symbol.address:
            return

        if removed:
            self.name_changed(symbol.address, "sub_%x" % symbol.address)
        else:
            self.name_changed(symbol.address, symbol.name)

    def name_changed(self, address, name):
        """
        A placeholder callback, which will get hooked / replaced once live.
        """
        pass


# ------------------------------------------------------------------------------
# UI (SidebarWidget implementation)
# ------------------------------------------------------------------------------

# Store a temporary reference to the global integration object so the widget can access it.
# This is a common pattern for plugins injecting complex logic into the BN UI.
_INTEGRATION_HACK = None

class LighthouseWidget(SidebarWidget):
    """
    The main Sidebar Widget container for the Lighthouse UI.
    """
    def __init__(self, name, frame, data):
        SidebarWidget.__init__(self, name)
        
        # This 'data' object is the BinaryView (dctx in Lighthouse terms)
        dctx = data 

        # We must acquire the context to get the core integration object 
        # (which manages the LighthouseCore state)
        global _INTEGRATION_HACK
        core = _INTEGRATION_HACK 

        # This call creates/fetches the LighthouseContext for the current BinaryView
        # and starts the subsystems (metadata, painter, director) if needed.
        lctx = core.get_context(dctx)
        
        # The core logic requires the underlying Qt widget to be populated by the
        # create_coverage_overview function defined in lighthouse/integration/core.py
        from lighthouse.ui import CoverageOverview
        CoverageOverview(lctx, self)
        
        # The parent constructor already handles UIActionHandler setup, so we skip it here.
        
    @property
    def visible(self):
        # FIX: Implement the .visible property expected by CoverageOverview.py's EventProxy
        return self.isVisible()


class LighthouseWidgetType(SidebarWidgetType):
    def __init__(self):
        # NOTE: Using placeholder 'L' icon for now, real icon is needed for release.
        icon = QImage(56, 56, QImage.Format_RGB32)
        icon.fill(0)

        p = QPainter()
        p.begin(icon)
        p.setFont(QFont("Open Sans", 56))
        p.setPen(QColor(255, 255, 255, 255))
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "L")
        p.end()

        # The internal name "Lighthouse" is used to focus the widget in show_dockable
        SidebarWidgetType.__init__(self, icon, "Lighthouse")

    def createWidget(self, frame, data):
        # This callback is called by Binary Ninja to create the actual widget.
        return LighthouseWidget("Lighthouse", frame, data)

    def defaultLocation(self):
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):
        # We want one instance per BinaryView (per database)
        return SidebarContextSensitivity.PerViewTypeSidebarContext


# Set the hack reference to the integration object
def set_integration_hack(integration_object):
    global _INTEGRATION_HACK
    _INTEGRATION_HACK = integration_object

# NOTE: The SidebarWidgetType registration now occurs through the integration hook below:
# Sidebar.addSidebarWidgetType(LighthouseWidgetType())