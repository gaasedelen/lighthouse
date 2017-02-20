from idaapi import plugin_t

from lighthouse.ui import *
from lighthouse.util import *
from lighthouse.parsers import *
from lighthouse.coverage import *
from lighthouse.painting import *

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

class Lighthouse(plugin_t):
    """
    The Lighthouse IDA Plugin.
    """

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_MOD
    comment = "Code Coverage Explorer"
    help = ""
    wanted_name = "Lighthouse"
    wanted_hotkey = ""

    def __init__(self):

        # plugin color palette
        self.palette = LighthousePalette()
        self.color = 0

        #----------------------------------------------------------------------

        # the database coverage data conglomerate
        self.db_coverage = DatabaseCoverage()

        # hexrays hooks
        self._hxe_events = None

        # plugin qt elements
        self._ui_coverage_list = CoverageOverview(self.db_coverage)

        # members for the 'Load Code Coverage' menu entry
        self._icon_id_load     = idaapi.BADADDR
        self._action_name_load = "lighthouse:load_coverage"

        # members for the 'Coverage Overview' menu entry
        self._icon_id_overview     = idaapi.BADADDR
        self._action_name_overview = "lighthouse:coverage_overview"

    #--------------------------------------------------------------------------
    # IDA Plugin Overloads
    #--------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        # attempt plugin initialization
        try:
            self._install_plugin()

        # failed to integrate plugin, log and skip loading
        except Exception as e:
            logger.exception("Failed to initialize")
            return idaapi.PLUGIN_SKIP

        # loaded successfully, print the Lighthouse banner
        self.print_banner()
        logger.info("Successfully initialized")

        # tell IDA to keep the plugin loaded (everything is okay)
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
            return

        # ensure hexrays is loaded & ready for use
        if not idaapi.init_hexrays_plugin():
            raise RuntimeError("HexRays is not available yet")

        # map our callback function to an actual member since we can't properly
        # remove bindings from IDA callback registrations otherwise. it also
        # makes installation tracking/status easier.
        self._hxe_events = self._hexrays_callback

        # install the callback handler
        idaapi.install_hexrays_callback(self._hxe_events)

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

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _install_ui(self):
        """
        Initialize & integrate all UI elements.
        """

        # install the 'Load Coverage' file dialog
        self._install_load_file_dialog()
        self._install_open_coverage_overview()

    def _install_load_file_dialog(self):
        """
        Install the 'File->Load->Code Coverage File(s)...' menu entry.
        """

        # createa a custom IDA icon
        self._icon_id_load = idaapi.load_custom_icon(
            #data=str(QtCore.QResource(":/icons/overview.png").data())
            data=str(open(resource_file("icons/load.png"), "rb").read())
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
            idaapi.SETMENU_APP       # We want to append the action after ^
        )
        if not result:
            RuntimeError("Failed to attach load action to 'File/Load file/' dropdown")

        logger.info("Installed the 'Load Code Coverage' menu entry")

    def _install_open_coverage_overview(self):
        """
        Install the 'View->Open subviews->Coverage Overview' menu entry.
        """

        # createa a custom IDA icon
        self._icon_id_overview = idaapi.load_custom_icon(
            #data=str(QtCore.QResource(":/icons/overview.png").data())
            data=str(open(resource_file("icons/overview.png"), "rb").read())
        )

        # describe the action
        # add an menu entry to the options dropdown on the IDA toolbar
        action_desc = idaapi.action_desc_t(
            self._action_name_overview,               # The action name.
            "~C~overage Overview",                    # The action text.
            IDACtxEntry(self.open_coverage_overview), # The action handler.
            None,                                     # Optional: action shortcut
            "Open database code coverage overview",   # Optional: tooltip
            self._icon_id_overview                    # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register open coverage overview action with IDA")

        # attach the action to the File-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "View/Open subviews/Hex dump", # Relative path of where to add the action
            self._action_name_overview,    # The action ID (see above)
            idaapi.SETMENU_INS             # We want to append the action after ^
        )
        if not result:
            RuntimeError("Failed to attach open action to 'subviews' dropdown")

        logger.info("Installed the 'Coverage Overview' menu entry")

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
        self._uninstall_open_coverage_overview()
        self._uninstall_load_file_dialog()

    def _uninstall_load_file_dialog(self):
        """
        Remove the 'File->Load file->Code Coverage File(s)...' menu entry.
        """

        # remove the entry from the File-> menu
        result = idaapi.detach_action_from_menu(
            "File/Load file/",                 # Relative path of where we put the action
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

        logger.info("Uninstalled the 'Load Code Coverage' menu entry")

    def _uninstall_open_coverage_overview(self):
        """
        Remove the 'View->Open subviews->Coverage Overview' menu entry.
        """

        # remove the entry from the View-> menu
        result = idaapi.detach_action_from_menu(
            "View/Open subviews/Hex dump",    # Relative path of where we put the action
            self._action_name_overview)
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self._action_name_overview)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_overview)
        self._icon_id_overview = idaapi.BADADDR

        logger.info("Uninstalled the 'Coverage Overview' menu entry")

    #--------------------------------------------------------------------------
    # UI - Actions
    #--------------------------------------------------------------------------

    def load_code_coverage(self):
        """
        Interactive file dialog based loading of Code Coverage.
        """

        # prompt the user with a QtFileDialog to select coverage files.
        coverage_files = self._select_code_coverage_files()
        if not coverage_files:
            return

        # load the selected code coverage files into the plugin core
        for filename in coverage_files:
            self.load_code_coverage_file(filename)

        # done loading coverage files, bake metrics
        self.db_coverage.finalize(self.palette)

        #
        # depending on if IDA is using a dark or light theme, we paint
        # coverage with a color that will hopefully keep things readable.
        # determine whether to use a 'dark' or 'light' paint
        #

        bg_color = get_disas_bg_color()
        if bg_color.lightness() > 255.0/2:
            self.color = self.palette.paint_light
        else:
            self.color = self.palette.paint_dark

        # color the database based on coverage
        paint_coverage(self.db_coverage, self.color)

        # show the coverage overview
        self.open_coverage_overview()

    def open_coverage_overview(self):
        """
        Open the Coverage Overview dialog.
        """

        # refresh the coverage overview model before making it visible
        self._ui_coverage_list.update_model(self.db_coverage)

        # make the dialog visible
        self._ui_coverage_list.Show()

    def _select_code_coverage_files(self):
        """
        Open the 'Load Code Coverage' dialog and capture file selections.
        """

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtWidgets.QFileDialog(None, 'Open Code Coverage File(s)')
        file_dialog.setFileMode(QtWidgets.QFileDialog.ExistingFiles)

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

        # extract the coverage relevant to this IDB (well, the root binary)
        root_filename = idaapi.get_root_filename()
        coverage_blocks = coverage_data.filter_by_module(root_filename)

        # enlighten the databases' coverage hub to this new data
        base = idaapi.get_imagebase()
        self.db_coverage.add_coverage(base, coverage_blocks)

    def _hexrays_callback(self, event, *args):
        """
        HexRays callback event handler.
        """

        if event == idaapi.hxe_text_ready:
            vdui = args[0]

            # grab the coverage data for the function of this decompilation
            try:
                function_coverage = self.db_coverage.functions[vdui.cfunc.entry_ea]

            # presumably, function does not exist for this function
            except KeyError:
                return 0

            # if coverage is zero, nothing to paint
            if not function_coverage.percent_instruction:
                return 0

            # paint the decompilation for this function
            paint_hexrays(vdui, function_coverage, self.color)

        return 0

#------------------------------------------------------------------------------
# IDA Plugin Palette
#------------------------------------------------------------------------------

class LighthousePalette(object):
    """
    Color Palette for the Lighthouse plugin.

    TODO: external customization
    """

    def __init__(self):
        """
        Initialize default palette colors for Lighthouse.
        """

        # blue to red - 'dark' theme
        self.coverage_bad  = QtGui.QColor(221, 0, 0)
        self.coverage_good = QtGui.QColor(51, 153, 255)

        # green to red - 'light' theme
        #self.coverage_bad  = QtGui.QColor(207, 31, 0)
        #self.coverage_good = QtGui.QColor(75, 209, 42)

        # TODO: unused for now
        self.profiling_cold = QtGui.QColor(0,0,0)
        self.profiling_hot  = QtGui.QColor(0,0,0)

        # color used for painting disassembly/graph/hexrays
        self.paint_dark  = 0x00990000    # NOTE: IDA uses BBGGRR
        self.paint_light = 0x00C8E696
