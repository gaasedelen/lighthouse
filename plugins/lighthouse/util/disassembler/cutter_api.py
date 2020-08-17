# -*- coding: utf-8 -*-
import os
import sys
import logging
import functools
import threading

import cutter
import CutterBindings

from .api import DisassemblerCoreAPI, DisassemblerContextAPI
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

    #@functools.wraps(function)
    #def wrapper(*args, **kwargs):
    #    return function(*args, **kwargs)
    #return wrapper
    return function

#------------------------------------------------------------------------------
# Disassembler API
#------------------------------------------------------------------------------

class CutterCoreAPI(DisassemblerCoreAPI):
    """
    The Cutter implementation of the disassembler API abstraction.
    """
    NAME = "CUTTER"

    def __init__(self):
        super(CutterCoreAPI, self).__init__()
        self._init_version()
        self._widgets = {}

    def _init_version(self):
        version_string = cutter.version()
        major, minor, patch = map(int, version_string.split('.'))

        # save the version number components for later use
        self._version_major = major
        self._version_minor = minor
        self._version_patch = patch

        # export Cutter Core
        self._core = CutterBindings.CutterCore.instance()
        logger.info('self._core: {}'.format(type(self._core)))
        self._config = CutterBindings.Configuration.instance()
        logger.info('self._config: {}'.format(type(self._config)))

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
    # Disassembler Universal APIs
    #--------------------------------------------------------------------------

    def get_disassembler_user_directory(self):

        # TODO/CUTTER: is there an API for this yet?!? or at least the plugin dir...
        if sys.platform == "linux" or sys.platform == "linux2":
            return os.path.expanduser("~/.local/share/RadareOrg/Cutter")
        elif sys.platform == "darwin":
            raise RuntimeError("TODO OSX")
        elif sys.platform == "win32":
            return os.path.join(os.getenv("APPDATA"), "RadareOrg", "Cutter")

        raise RuntimeError("Unknown operating system")

    def get_disassembly_background_color(self):
        return self._config.getColor("gui.background")

    def is_msg_inited(self):
        return True

    def warning(self, text):
        pass
        #self.main.messageBoxWarning('Lighthouse warning', text)

    def message(self, message):
        cutter.message(message)



    #--------------------------------------------------------------------------
    # UI APIs
    #--------------------------------------------------------------------------

    def register_dockable(self, dockable_name, create_widget_callback):
        logger.warning('Method register_dockable not implemented for Cutter')
        self._widgets[dockable_name] = create_widget_callback

    def create_dockable_widget(self, parent, dockable_name):
        logger.warning('Method create_dockable_widget not implemented for Cutter')
        widget = cutter.CutterDockWidget(parent)
        widget.setWindowTitle(dockable_name)
        action = QtWidgets.QAction('Lighthouse coverage table')
        action.setCheckable(True)
        main.addPluginDockWidget(widget, action)
        return widget

    def show_dockable(self, dockable_name):
        logger.warning('Method show_dockable not implemented for Cutter')
        self._widgets[dockable_name].toggleDockWidget(true)
        pass

    def hide_dockable(self, dockable_name):
        logger.warning('Method hide_dockable not implemented for Cutter')
        pass



    #--------------------------------------------------------------------------
    # Function Prefix API
    #--------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UI
#------------------------------------------------------------------------------

class CutterContextAPI(DisassemblerContextAPI):
    """
    A dockable Qt widget for Cutter.
    """

    def __init__(self, dctx):
        super(CutterContextAPI, self).__init__(dctx)

        # configure dockable widget container
        self._widget = QtWidgets.QWidget()
        self._dockable = QtWidgets.QDockWidget('window_title')
        self._dockable.setWidget(self._widget)
        #self._dockable.setWindowIcon(self._window_icon)
        self._dockable.setAttribute(QtCore.Qt.WA_DeleteOnClose)
        self._dockable.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding,
            QtWidgets.QSizePolicy.Expanding
        )
        self._widget.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding,
            QtWidgets.QSizePolicy.Expanding
        )

        # export Cutter Core
        self._core = CutterBindings.CutterCore.instance()
        logger.info('self._core: {}'.format(type(self._core)))
        self._config = CutterBindings.Configuration.instance()
        logger.info('self._config: {}'.format(type(self._config)))

    def show(self):
        #pass
        self._dockable.show()
        self._dockable.raise_()

    def setmain(self, main):
        #pass

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

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    def busy(self):
        #TODO
        return False

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    def get_current_address(self):
        return self._core.getOffset()

    def get_database_directory(self):
        # TODO/CUTTER: Use Cutter API
        return cutter.cmdj('ij')['core']['file']

    def get_function_addresses(self):

        #
        # TODO/CUTTER: Use Cutter API
        #
        # TODO/CUTTER: Apparently, some of the addresses returned by this are
        # ***NOT*** valid function addresses. they fail when passed into get_function_at()
        #

        logger.debug('Calling get_function addresses')

        maybe_functions = [x['offset'] for x in cutter.cmdj('aflj')]

        #
        # TODO/CUTTER/HACK: this is a gross hack to ensure lighthouse wont choke on *non*
        # function addresses given in maybe_functions
        #

        good = set()
        for address in maybe_functions:
            if self.get_function_at(address):
                good.add(address)

        # return a list of *ALL FUNCTION ADDRESSES* in the database
        return list(good)

    def get_function_name_at(self, address):
        # TODO/CUTTER: Use Cutter API
        func = self.get_function_at(address)
        if not func:
            return None
        #print('Function at {} is {}'.format(address, func['name']))
        return func['name']

    def get_function_raw_name_at(self, address):
        return self.get_function_at(address)['name']

    def get_imagebase(self):
        # TODO/CUTTER: Use Cutter API
        return cutter.cmdj('ij')['bin']['baddr']

    def get_function_at(self, address):
        # TODO/CUTTER: Use Cutter API
        return cutter.cmdj('afij @ ' + str(address))[0]
        #try:
        #    return cutter.cmdj('afij @ ' + str(address))[0]
        #except IndexError:
        #    return None

    def get_root_filename(self):
        # TODO/CUTTER: Use Cutter API
        return os.path.basename(cutter.cmdj('ij')['core']['file'])

    def navigate(self, address):
        return self._core.seek(address)

    def navigate_to_function(self, function_address, address):
        logger.warning('Method navigate_to_function not implemented for Cutter')
        pass

    def set_function_name_at(self, function_address, new_name):
        old_name = self.get_function_raw_name_at(function_address)
        self._core.renameFunction(old_name, new_name)

    def create_rename_hooks(self):
        return RenameHooks(self._core)

    PREFIX_SEPARATOR = "▁" # Unicode 0x2581


class RenameHooks(object):
    def __init__(self, core):
        self._core = core

    def hook(self):
        #self._core.functionRenamed.connect(self.update)
        pass

    def unhook(self):
        #self._core.functionRenamed.disconnect(self.update)
        pass

    def update(self, old_name, new_name):
        logger.debug('Received update event!', old_name, new_name)
        # TODO/CUTTER: HOW DO I GET A FUNCITON'S ADDRESS BY NAME??
        #self.renamed(address, new_name)
        pass

    # placeholder, this gets replaced in metadata.py
    #def renamed(self, address, new_name):
    #    pass
