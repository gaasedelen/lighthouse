# -*- coding: utf-8 -*-
import os
import sys
import logging
import functools
import threading

import cutter
import CutterBindings

from .api import DisassemblerAPI, DockableShim
from ..qt import *
from ..misc import is_mainthread, not_mainthread

logger = logging.getLogger("Lighthouse.API.Cutter")

#------------------------------------------------------------------------------
# Utils
#------------------------------------------------------------------------------

def execute_sync(function):
    """
    TODO/CUTTER: Synchronize with the disassembler for safe database access.
    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        return function(*args, **kwargs)
    return wrapper

#------------------------------------------------------------------------------
# Disassembler API
#------------------------------------------------------------------------------

class CutterAPI(DisassemblerAPI):
    """
    The Cutter implementation of the disassembler API abstraction.
    """
    NAME = "CUTTER"

    def __init__(self):
        super(CutterAPI, self).__init__()
        self._init_version()

    def _init_version(self):
        version_string = cutter.version()
        major, minor, patch = map(int, version_string.split('.'))

        # save the version number components for later use
        self._version_major = major
        self._version_minor = minor
        self._version_patch = patch

        # export Cutter Core
        self._core = CutterBindings.CutterCore.instance()
        self._config = CutterBindings.Configuration.instance()

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def headless(self):
        return False

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
            qt_mainthread.execute_fast(ff)
        return wrapper

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    def create_rename_hooks(self):
        class RenameHooks(object):
            def __init__(self, core):
                self._core = core

            def hook(self):
                #self._core.functionRenamed.connect(self.update)
                print("TODO/CUTTER: Hook rename")

            def unhook(self):
                #self._core.functionRenamed.disconnect(self.update)
                print("TODO/CUTTER: Unhook rename")

            def update(self, old_name, new_name):
                print('Received update event!', old_name, new_name)

        return RenameHooks(self._core)

    def get_current_address(self):
        return self._core.getOffset()

    def get_function_at(self, address):
        # TODO/CUTTER: Use Cutter API
        return cutter.cmdj('afij @ ' + str(address))[0]

    def get_database_directory(self):
        # TODO/CUTTER: Use Cutter API
        return cutter.cmdj('ij')['core']['file']

    def get_disassembler_user_directory(self):
        if sys.platform == "linux" or sys.platform == "linux2":
            return os.path.expanduser("~/.local/share/RadareOrg/Cutter")
        elif sys.platform == "darwin":
            raise RuntimeError("TODO OSX")
        elif sys.platform == "win32":
            return os.path.join(os.getenv("APPDATA"), "RadareOrg", "Cutter")
        raise RuntimeError("Unknown operating system")

    def get_function_addresses(self):
        # TODO/CUTTER: Use Cutter API
        return [x['offset'] for x in cutter.cmdj('aflj')]

    def get_function_name_at(self, address):
        # TODO/CUTTER: Use Cutter API
        return self.get_function_at(address)['name']

    def get_function_raw_name_at(self, address):
        return self.get_function_at(address)['name']

    def get_imagebase(self):
        # TODO/CUTTER: Use Cutter API
        return cutter.cmdj('ij')['bin']['baddr']

    def get_root_filename(self):
        # TODO/CUTTER: Use Cutter API
        return os.path.basename(cutter.cmdj('ij')['core']['file'])

    def navigate(self, address):
        return self._core.seek(address)

    def set_function_name_at(self, function_address, new_name):
        old_name = self.get_function_raw_name_at(function_address)
        self._core.renameFunction(old_name, new_name)

    def message(self, message):
        cutter.message(message)

    #--------------------------------------------------------------------------
    # UI API Shims
    #--------------------------------------------------------------------------

    def get_disassembly_background_color(self):
        return self._config.getColor("gui.background")

    def is_msg_inited(self):
        return True

    def warning(self, text):
        self.main.messageBoxWarning('Lighthouse warning', text)

    #--------------------------------------------------------------------------
    # Function Prefix API
    #--------------------------------------------------------------------------

    PREFIX_SEPARATOR = "▁" # Unicode 0x2581

#------------------------------------------------------------------------------
# UI
#------------------------------------------------------------------------------

class DockableWindow(DockableShim):
    """
    A dockable Qt widget for Cutter.
    """

    def __init__(self, window_title, icon_path):
        super(DockableWindow, self).__init__(window_title, icon_path)

        # configure dockable widget container
        self._widget = QtWidgets.QWidget()
        self._dockable = QtWidgets.QDockWidget(window_title)
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

    def show(self):
        self._dockable.show()
        self._dockable.raise_()

    def setmain(self, main):

        #
        # NOTE HACK:
        #   this is a little dirty, but it's needed because it's not as
        #   easy as get_qt_main_window() to get the main dock in Cutter
        #

        self._main = main
        # self._widget.setParent(main)

        # dock the widget inside Cutter main dock
        self._action = QtWidgets.QAction('Lighthouse coverage table')
        self._action.setCheckable(True)
        main.addPluginDockWidget(self._dockable, self._action)

