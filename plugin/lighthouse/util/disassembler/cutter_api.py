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
    Synchronize with the disassembler for safe database access.
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
            ff()

        return wrapper

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    def create_rename_hooks(self):
        class RenameHooks(object):
            def __init__(self, core):
                self._core = core

            def hook(self):
                print('Hooked rename')
                QtCore.QObject.connect(self._core,
                        QtCore.SIGNAL('functionRenamed(const QString, const QString)'),
                        self.update)

            def unhook(self):
                print('UnHooked rename')
                QtCore.QObject.disconnect(self._core,
                        QtCore.SIGNAL('functionRenamed(const QString, const QString)'),
                        self.update)

            def update(self, old_name, new_name):
                # TODO Wtf this is not triggered?
                print('Received update event!', old_name, new_name)

        return RenameHooks(self._core)

    def get_current_address(self):
        return self._core.getOffset()

    def get_function_at(self, address):
        # TODO Use Cutter API
        return cutter.cmdj('afij @ ' + str(address))[0]

    @execute_read.__func__
    def get_database_directory(self):
        # TODO Use Cutter API
        return cutter.cmdj('ij')['core']['file']

    def get_disassembler_user_directory(self):
        return os.path.split(binaryninja.user_plugin_path())[0]

    @not_mainthread
    def get_function_addresses(self):
        # TODO Use Cutter cache/API
        return [x['offset'] for x in cutter.cmdj('aflj')]

    @not_mainthread
    def get_function_name_at(self, address):
        # TODO User Cutter API
        return self.get_function_at(address)['name']

    @execute_read.__func__
    def get_function_raw_name_at(self, address):
        return self.get_function_at(address)['name']

    @not_mainthread
    def get_imagebase(self):
        # TODO Use Cutter API
        return cutter.cmdj('ij')['bin']['baddr']

    @not_mainthread
    def get_root_filename(self):
        # TODO Use Cutter API
        return os.path.basename(cutter.cmdj('ij')['core']['file'])

    def navigate(self, address):
        return self._core.seek(address)

    @execute_write.__func__
    def set_function_name_at(self, function_address, new_name):
        old_name = self.get_function_raw_name_at(function_address)
        self._core.renameFunction(old_name, new_name)
        # TODO Fix refresh :)

    @staticmethod
    def get_color(red, green, blue):
        return QtGui.QColor(red, green, blue)

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
        #
        # NOTE/HACK:
        #   this is a little dirty, but is used to set the default width
        #   of the coverage overview / dockable widget when it is first shown
        #

        #default_width = self._widget.sizeHint().width()
        #self._dockable.setMinimumWidth(default_width)

        # show the widget
        self._dockable.show()
        self._dockable.raise_()

        # undo the HACK
        #self._dockable.setMinimumWidth(0)

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

