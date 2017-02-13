from idaapi import plugin_t

from lighthouse.ui import *
from lighthouse.util import *
from lighthouse.parsers import *
from lighthouse.coverage import *
from lighthouse.painting import *

# start the global logger *once*
if not logging_started():
    logger = start_logging()

#--------------------------------------------------------------------------
# PySide --> PyQt5 - COMPAT
#--------------------------------------------------------------------------

if using_pyqt5():
    QFileDialog = QtWidgets.QFileDialog
else:
    QFileDialog = QtGui.QFileDialog

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

        # coverage color, a dark blue-ish
        self.color = 0x00AA0000               # NOTE: IDA uses BBGGRR

        #----------------------------------------------------------------------

        # the database coverage
        self.db_coverage = DatabaseCoverage()

        # members for the 'Load Code Coverage' file dialog / menu / action
        self._icon_id_load     = idaapi.BADADDR
        self._action_name_load = "lighthouse:load_coverage"

        # hexrays hooks
        self._hxe_events = None

        # UI Elements
        self._ui_coverage_list = CoverageOverview(self.db_coverage)

    #--------------------------------------------------------------------------
    # IDA Plugin Overloads
    #--------------------------------------------------------------------------

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

    #--------------------------------------------------------------------------
    # Initialization
    #--------------------------------------------------------------------------

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
        self._install_hexrays_hooks()

    def _install_hexrays_hooks(self, _=None):
        """
        Install Hexrays hook listeners.
        """

        # event hooks already installed for hexrays
        if self._hxe_events:
            return 0

        # ensure hexrays is available
        if not idaapi.init_hexrays_plugin():
            raise RuntimeError("HexRays is not available yet")
            return 0

        # map the function to an actual member since we can't properly remove
        # bindings from callback registrations. also makes installation
        # tracking/status easier.
        self._hxe_events = self._hexrays_callback

        # install the callback handler
        idaapi.install_hexrays_callback(self._hxe_events)
        return 0

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

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

    #--------------------------------------------------------------------------
    # Termination
    #--------------------------------------------------------------------------

    def _uninstall_plugin(self):
        """
        Cleanup & uninstall the plugin from IDA.
        """
        self._uninstall_ui()
        # TODO: uninstall hxe hooks

    #--------------------------------------------------------------------------
    # Termination - UI
    #--------------------------------------------------------------------------

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

    #--------------------------------------------------------------------------
    # UI - Actions
    #--------------------------------------------------------------------------

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

        # color the database based on coverage
        paint_coverage(self.db_coverage, self.color)

        # update list view
        self._ui_coverage_list.update_model(self.db_coverage)
        self._ui_coverage_list.Show()

    def _select_code_coverage_files(self):
        """
        Open the 'Load Code Coverage' dialog and capture file selections.
        """

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QFileDialog(None, 'Open Code Coverage File(s)')
        file_dialog.setFileMode(QFileDialog.ExistingFiles)

        # prompt the user with the file dialog, and await filename(s)
        filenames, _ = file_dialog.getOpenFileNames()
        logger.debug("Captured filenames from file dialog:")
        logger.debug(filenames)

        return filenames

    #--------------------------------------------------------------------------
    # Misc
    #--------------------------------------------------------------------------

    def load_code_coverage_file(self, filename):
        """
        Load code coverage file by filename.

        NOTE: At this time only binary drcov logs are supported.
        """

        # load coverage data from file
        coverage_data = DrcovData(filename)

        # normalize coverage to the database
        self.db_coverage = DatabaseCoverage()

        # extract the coverage relevant to this IDB (well, the root binary)
        root_filename = idaapi.get_root_filename()
        coverage_blocks = coverage_data.filter_by_module(root_filename)

        # enlight the databases' coverage hub to this new data
        base = idaapi.get_imagebase()
        self.db_coverage.add_coverage(base, coverage_blocks)

    def _hexrays_callback(self, event, *args):
        """
        HexRays callback event handler.
        """

        # args[0] == vdui
        if event == idaapi.hxe_text_ready:
            logger.debug("Caught HexRays hxe_text_ready event")
            paint_hexrays(args[0], self.db_coverage, self.color)

        return 0
