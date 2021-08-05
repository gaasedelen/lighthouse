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
        self._widgets[dockable_name] = create_widget_callback(dockable_name, self.main, None)

    def create_dockable_widget(self, parent, dockable_name):
        action = QtWidgets.QAction('Lighthouse coverage table')
        action.setCheckable(True)
        widget = cutter.CutterDockWidget(parent, action)
        inner_widget = DockableWidget(widget)
        widget.setWidget(inner_widget)
        widget.setWindowTitle(dockable_name)
        widget.setObjectName('Coverage Overview')
        parent.addPluginDockWidget(widget, action)
        return inner_widget

    def show_dockable(self, dockable_name):
        self._widgets[dockable_name].toggleDockWidget(True)

    def hide_dockable(self, dockable_name):
        self._widgets[dockable_name].toggleDockWidget(False)



    #--------------------------------------------------------------------------
    # Helper methods
    #--------------------------------------------------------------------------

    def highlight(self, node, color):
        logger.debug('Highlighting node {} with color {}'.format(node, color))
        self._core.getBBHighlighter().highlight(node, color)

    def unhighlight(self, address):
        self._core.getBBHighlighter().clear(address)



#------------------------------------------------------------------------------
# UI
#------------------------------------------------------------------------------

class CutterContextAPI(DisassemblerContextAPI):
    """
    A dockable Qt widget for Cutter.
    """

    def __init__(self, dctx):
        super(CutterContextAPI, self).__init__(dctx)

        # export Cutter Core
        self._core = CutterBindings.CutterCore.instance()
        logger.info('self._core: {}'.format(type(self._core)))
        self._config = CutterBindings.Configuration.instance()
        logger.info('self._config: {}'.format(type(self._config)))
        logger.debug('Exported Cutter core')

        self.cache = Cache(self)
        self._image_base = None

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
        logger.debug('Getting current address')
        return self._core.getOffset()

    def get_database_directory(self):
        # TODO/CUTTER: Use Cutter API
        logger.debug('Getting database directory')
        return cutter.cmdj('ij')['core']['file']

    def get_function_addresses(self):

        #
        # TODO/CUTTER: Use Cutter API
        #
        # TODO/CUTTER: Apparently, some of the addresses returned by this are
        # ***NOT*** valid function addresses. they fail when passed into get_function_at()
        #
        logger.debug('Getting function addresses')

        #maybe_functions = [x['offset'] for x in cutter.cmdj('aflj')]
        maybe_functions = [x['offset'] for x in self.cache.functions]

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
        logger.debug('Getting function name at')
        func = self.get_function_at(address)
        if not func:
            return None
        #print('Function at {} is {}'.format(address, func['name']))
        return func['name']

    def get_function_raw_name_at(self, address):
        logger.debug('Getting function raw name at')
        return self.get_function_at(address)['name']

    def get_imagebase(self):
        # TODO/CUTTER: Use Cutter API
        logger.debug('Getting image base')
        if self._image_base:
            return self._image_base
        self._image_base = cutter.cmdj('ij')['bin']['baddr']
        return self._image_base

    def get_function_at(self, address):
        logger.debug('Getting function at')
        try:
            return self.cache.get_function_at(address)
        except IndexError:
            return None

    def get_root_filename(self):
        # TODO/CUTTER: Use Cutter API
        logger.debug('Getting root filename')
        return os.path.basename(cutter.cmdj('ij')['core']['file'])

    def navigate(self, address):
        logger.debug('Navigating')
        return self._core.seek(address)

    def navigate_to_function(self, function_address, address):
        self._core.seek(address)

    def set_function_name_at(self, function_address, new_name):
        logger.debug('Setting function name at')
        old_name = self.get_function_raw_name_at(function_address)
        self._core.renameFunction(old_name, new_name)

    def create_rename_hooks(self):
        logger.debug('Creating rename hooks')
        return RenameHooks(self._core)

    PREFIX_SEPARATOR = "▁" # Unicode 0x2581


class RenameHooks(object):
    def __init__(self, core):
        self._core = core

    def hook(self):
        self._core.functionRenamed.connect(self.update)
        pass

    def unhook(self):
        self._core.functionRenamed.disconnect()
        pass

    def update(self, old_name, new_name):
        logger.debug('Received update event!', old_name, new_name)
        # TODO/CUTTER: HOW DO I GET A FUNCITON'S ADDRESS BY NAME??
        self.renamed(address, new_name)
        self._core.triggerRefreshAll()
        #pass

    # placeholder, this gets replaced in metadata.py
    #def renamed(self, address, new_name):
    #    pass


class DockableWidget(QtWidgets.QWidget):

    @property
    def visible(self):
        return self.isVisible()

    @visible.setter
    def visible(self, value):
        self.setVisible(value)


class Cache:
    def __init__(self, context):
        self.context = context
        self._functions = None

    def initialize(self):
        logger.debug('Initializing cache')
        self._functions = cutter.cmdj('aflj')

    @property
    def functions(self):
        if not self._functions:
            self.initialize()
        return self._functions

    def get_function_at(self, address):
        logger.debug('Using cache')
        return next(filter(lambda f: f['offset'] == address, self.functions), None)
