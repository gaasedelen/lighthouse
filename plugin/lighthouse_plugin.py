from idaapi import plugin_t
from PySide import QtCore, QtGui

from lighthouse.ui import *
from lighthouse.util import start_logging, logging_started, lmsg

# start the global logger *once*
if not logging_started():
    logger = start_logging()

#------------------------------------------------------------------------------
# IDA Plugin
#------------------------------------------------------------------------------

PLUGIN_VERSION = "0.1.0"
AUTHORS        = "Markus Gaasedelen"
DATE           = "2017"

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return Lighthouse()

#------------------------------------------------------------------------------
# IDA Plugin
#------------------------------------------------------------------------------

class Lighthouse(plugin_t):
    """
    The Lighthouse IDA Plugin.
    """

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_MOD
    comment = "Code Coverage Visualization"
    help = ""
    wanted_name = "Lighthouse"
    wanted_hotkey = ""

    def __init__(self):

        #
        # Member Decleration
        #

        # 'Load Code Coverage' file dialog variables
        self._icon_id_load     = idaapi.BADADDR
        self._action_name_load = "lighthouse:load_coverage"

    #----------------------------------------------------------------------
    # IDA Plugin Overloads
    #----------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        # perform plugin initialization & integration
        try:
            self._install_plugin()

        # failed to integrate plugin, log and skip loading
        except Exception as e:
            logger.exception("Failed to initialize")
            return idaapi.PLUGIN_SKIP

        # print the Lighthouse banner and log success
        self.print_banner()
        logger.info("Successfully initialized")

        # keep the plugin loaded
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        idaapi.warning("The Lighthouse plugin cannot be run as a script.")

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """

        # attempt to cleanup after ourselves
        try:
            self._uninstall_plugin()

        # failed to cleanly remove the plugin, log failure
        except Exception as e:
            logger.exception("Failed to cleanly unload the plugin")

        logger.info("-"*75)
        logger.info("Plugin terminated")

    #----------------------------------------------------------------------
    # Initialization
    #----------------------------------------------------------------------

    def print_banner(self):
        """
        Print the Lighthouse plugin banner.
        """

        # build the main banner title
        banner_params = (PLUGIN_VERSION, AUTHORS, DATE)
        banner_title  = "Lighthouse v%s - (c) %s - %s" % banner_params

        # print plugin banner
        lmsg("")
        lmsg("-"*75)
        lmsg("---[ %s" % banner_title)
        lmsg("-"*75)
        lmsg("")

    def _install_plugin(self):
        """
        Initialize & integrate the plugin into IDA.
        """
        self._install_ui()

    #----------------------------------------------------------------------
    # Initialization - UI
    #----------------------------------------------------------------------

    def _install_ui(self):
        """
        Initialize & integrate all UI elements.
        """

        # install the 'Load Coverage' file dialog
        self._install_load_file_dialog()

    def _install_load_file_dialog(self):
        """
        Install the 'File->Load->Code Coverage File(s)...' UI entry.
        """

        # TODO: icon
        self._icon_id_load = idaapi.load_custom_icon(
            data=str(QtCore.QResource(":/icons/load.png").data())
        )

        # describe the action
        # add an menu entry to the options dropdown on the IDA toolbar
        action_desc = idaapi.action_desc_t(
            self._action_name_load,                   # The action name.
            "~C~ode Coverage File(s)...",             # The action text.
            IDACtxEntry(self.load_code_coverage),     # The action handler.
            None,                                     # Optional: action shortcut
            "Load a code coverage file for this IDB", # Optional: tooltip
            self._icon_id_load                        # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register load coverage action with IDA")

        # attach the action to the File-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "File/Load file/",       # Relative path of where to add the action
            self._action_name_load,  # The action ID (see above)
            idaapi.SETMENU_APP       # What we want to append the action after
        )
        if not result:
            RuntimeError("Failed to attach load action to 'File/Load file/' dropdown")

        # disable both menu items by default
        #self._enable_menu_items(False, False)

        logger.info("Installed the 'Load Code Coverage' file dialog")

    #----------------------------------------------------------------------
    # Termination
    #----------------------------------------------------------------------

    def _uninstall_plugin(self):
        """
        Cleanup & uninstall the plugin from IDA.
        """
        self._uninstall_ui()

    #----------------------------------------------------------------------
    # Termination - UI
    #----------------------------------------------------------------------

    def _uninstall_ui(self):
        """
        Cleanup & uninstall the plugin UI from IDA.
        """
        self._uninstall_load_file_dialog()

    def _uninstall_load_file_dialog(self):
        """
        Remove the 'File->Load file->Code Coverage File(s)...' UI entry.
        """

        # remove the entry from the File-> menu
        result = idaapi.detach_action_from_menu(
            "File/Load file/",       # Relative path of where to add the action
            self._action_name_load)
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self._action_name_load)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_load)
        self._icon_id_load = idaapi.BADADDR

        logger.info("Uninstalled the 'Load Code Coverage' file dialog")

    #----------------------------------------------------------------------
    # UI - Actions
    #----------------------------------------------------------------------

    def load_code_coverage(self):
        """
        Interactive (file dialog) based loading of Code Coverage.
        """

        # prompt the user with a QtFileDialog to select coverage files.
        coverage_files = self._select_code_coverage_files()
        if not coverage_files:
            return

        # load the selected code coverage files into the plugin core
        for filename in coverage_files:
            self.load_code_coverage_file(filename)

    def _select_code_coverage_files(self):
        """
        Open the 'Load Code Coverage' dialog and capture file selections.
        """

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtGui.QFileDialog(None, 'Open Code Coverage File(s)')
        file_dialog.setFileMode(QtGui.QFileDialog.ExistingFiles)

        # prompt the user with the file dialog, and await filename(s)
        filenames, _ = file_dialog.getOpenFileNames()
        logger.debug("Captured filenames from file dialog:")
        logger.debug(filenames)

        return filenames

    #----------------------------------------------------------------------
    # Coverage - Core
    #----------------------------------------------------------------------

    def load_code_coverage_file(self, filename):
        logger.debug("TODO: load code coverage file %s" % filename)
