from idaapi import plugin_t
from PySide import QtCore, QtGui

from lighthouse.ui import *
from lighthouse.parsers import *
from lighthouse.coverage import *
from lighthouse.painting import *
from lighthouse.util.ida import *
from lighthouse.util.log import start_logging, logging_started, lmsg

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

        # hooks
        self._idp_events = None
        self._hxe_events = None

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
        self._install_idp_hooks()
        #self._install_hexrays_hooks()

    def _install_idp_hooks(self):
        """
        Install the IDA Processor notification hooks.

        NOTE:

          We use some IDP hooks to install our hexrays hooks later in the
          loading process as the plugin seems to load before hexrays.

        """
        self._idp_events = IDPListener()

        # register handlers on the events to listen for
        self._idp_events.oldfile   = self._install_hexrays_hooks
        self._idp_events.newfile   = self._install_hexrays_hooks
        #self._idp_events.closebase = self._uninstall_hexrays

        # hook said events
        self._idp_events.hook()

    def _install_hexrays_hooks(self, _=None):
        """
        Install Hexrays hook listeners.
        """

        # event hooks already installed for hexrays
        if self._hxe_events:
            return 0

        # ensure hexrays is available
        if not idaapi.init_hexrays_plugin():
            logger.debug("hexrays not loaded")
            return 0

        # map the function to an actual member since we can't properly remove
        # bindings from callback registrations. also makes installation
        # tracking/status easier.
        self._hxe_events = self._hexrays_callback

        # install the callback handler
        idaapi.install_hexrays_callback(self._hxe_events)
        return 0

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
        self._uninstall_idp_hooks()
        # TODO: uninstall hxe hooks

    def _uninstall_idp_hooks(self):
        """
        Remove the installed IDA Processor notification hooks.
        """
        assert self._idp_events

        # remove the installed hooks
        self._idp_events.unhook()
        self._idp_events = None
        logger.debug("Removed IDP Hooks")

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

        self._install_hexrays_hooks()

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
    # HexRays
    #----------------------------------------------------------------------

    def _hexrays_callback(self, event, *args):
        """
        HexRays callback event handler.
        """
        if event == idaapi.hxe_text_ready:
            vdui = args[0]
            self._paint_hexrays(vdui, self.coverage)
        return 0

    #----------------------------------------------------------------------
    # Coverage - Core
    #----------------------------------------------------------------------

    def load_code_coverage_file(self, filename):
        """
        TODO
        """

        # load coverage data from file
        coverage_data = DrcovData(filename)

        # normalize coverage to the database
        base     = idaapi.get_imagebase()
        coverage = IDACoverage(base, coverage_data)
        color    = 0x00FF0000
        self.coverage = coverage

        # color the database based on coverage
        self._paint_coverage(coverage, color)

    def _paint_coverage(self, coverage, color):
        """
        Apply coverage colors to the IDB.
        """

        # paint tainted graph nodes
        self._paint_node_map(coverage.node_map, color)

        # paint individual instructions
        self._paint_instructions(coverage, color)

        # TODO: actually, we should do this on-request
        # paint hexrays
        #self._paint_hexrays(coverage)

    def _paint_node_map(self, node_map, color):
        """
        Paint touched nodes in the IDA Graph View.
        """
        for function_ea in node_map:
            color_nodes(function_ea, node_map[function_ea], color)

    def _paint_hexrays(self, vdui, coverage):
        """
        Paint hexrays.
        """
        decompilation_text = vdui.cfunc.get_pseudocode()

        # skip the parsing of variable declarations (hdrlines)
        line_start = vdui.cfunc.hdrlines + 1
        line_end   = decompilation_text.size()

        # build a mapping of line_number -> [citem indexes]
        line_map = {}
        for line_number in xrange(line_start, line_end):
            line = decompilation_text[line_number].line
            line_map[line_number] = extract_citem_indexes(line)
            #print "[%u] -" % line_number, indexes

        # retrieve the flowchart for this function
        flowchart = idaapi.FlowChart(idaapi.get_func(vdui.cfunc.entry_ea))

        # build a mapping of line_number -> nodes
        line2node = {}
        for line_number, citem_indexes in line_map.iteritems():

            nodes = set([])
            for index in citem_indexes:

                # get the code address of the current citem
                address = vdui.cfunc.treeitems[index].ea

                # walk the flowchart and find the basic block associated with this node
                found_block = None
                for bb in flowchart:
                    if bb.startEA <= address < bb.endEA:
                        found_block = bb
                        break
                else:
                    logger.warning("Failed to map node to basic block")
                    continue

                # add the found basic block id
                nodes.add(bb.id)

            # save the list of node ids identified for this decompiled line
            line2node[line_number] = nodes

        # now paint any decompiled line that holds a tainted node
        for line_number, node_indexes in line2node.iteritems():
            try:
                if node_indexes.intersection(coverage.node_map[vdui.cfunc.entry_ea]):
                    print "TAINTING LINE %u" % line_number
                    decompilation_text[line_number].bgcolor = 0x00FF2030
            except KeyError as e:
                pass

        idaapi.refresh_idaview_anyway()

    def _paint_instructions(self, coverage, color):
        """
        Paint touched instructions in the IDA Disassembly View.
        """
        for offset, size in coverage._coverage_data:
            color_items(coverage.base+offset, size, color)


def extract_citem_indexes(line):
    """
    Extract all ctree item indexes from given line of text.
    """
    indexes = []

    # lex COLOR_ADDR tokens from the line
    i = 0
    while i < len(line):

        # does this character mark the start of a new COLOR_* sequence?
        if line[i] == idaapi.COLOR_ON:

            # move past the COLOR_ON mark
            i += 1

            # is this sequence a COLOR_ADDR token?
            if ord(line[i]) == idaapi.COLOR_ADDR:

                # move past the COLOR_ADDR mark
                i += 1

                # parse out either the next 8, or 16 characters as a hex number
                citem_index = int(line[i:i+idaapi.COLOR_ADDR_SIZE], 16)
                i += idaapi.COLOR_ADDR_SIZE

                # save the extracted index
                indexes.append(citem_index)

                # skip to the next iteration with the modified i
                continue

        # nothing interesting was found, keep going
        i += 1

    # return all the citem indexes extracted from this line of text
    return indexes
