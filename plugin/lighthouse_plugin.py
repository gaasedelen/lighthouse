import os

from idaapi import plugin_t

from lighthouse.ui import *
from lighthouse.util import *
from lighthouse.parsers import *
from lighthouse.palette import LighthousePalette
from lighthouse.painting import CoveragePainter
from lighthouse.director import CoverageDirector
from lighthouse.metadata import DatabaseMetadata, metadata_progress

# start the global logger *once*
if not logging_started():
    logger = start_logging()

#------------------------------------------------------------------------------
# IDA Plugin
#------------------------------------------------------------------------------

PLUGIN_VERSION = "0.4.0"
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

        # the database coverage data conglomerate
        self.director = CoverageDirector(self.palette)

        # the coverage painter
        self.painter = CoveragePainter(self.director, self.palette)

        # plugin qt elements
        self._ui_coverage_overview = None

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

        # failed to initialize or integrate the plugin, log and skip loading
        except Exception as e:
            logger.exception("Failed to initialize")
            return idaapi.PLUGIN_SKIP

        # plugin loaded successfully, print the Lighthouse banner
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

        # attempt to cleanup and uninstall our plugin instance
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

        # create a custom IDA icon
        self._icon_id_load = idaapi.load_custom_icon(
            data=str(open(plugin_resource("icons/load.png"), "rb").read())
        )

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self._action_name_load,                   # The action name.
            "~C~ode Coverage File(s)...",             # The action text.
            IDACtxEntry(self.load_coverage),          # The action handler.
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
            RuntimeError("Failed action attach to 'File/Load file/' dropdown")

        logger.info("Installed the 'Load Code Coverage' menu entry")

    def _install_open_coverage_overview(self):
        """
        Install the 'View->Open subviews->Coverage Overview' menu entry.
        """

        # create a custom IDA icon
        self._icon_id_overview = idaapi.load_custom_icon(
            data=str(open(plugin_resource("icons/overview.png"), "rb").read())
        )

        # describe a custom IDA UI action
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

        # attach the action to the View-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "View/Open subviews/Hex dump", # Relative path of where to add the action
            self._action_name_overview,    # The action ID (see above)
            idaapi.SETMENU_INS             # We want to insert the action before ^
        )
        if not result:
            RuntimeError("Failed action attach to 'View/Open subviews' dropdown")

        logger.info("Installed the 'Coverage Overview' menu entry")

    #--------------------------------------------------------------------------
    # Termination
    #--------------------------------------------------------------------------

    def _uninstall_plugin(self):
        """
        Cleanup & uninstall the plugin from IDA.
        """
        self._uninstall_ui()

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
            "File/Load file/",
            self._action_name_load
        )
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
            "View/Open subviews/Hex dump",
            self._action_name_overview
        )
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

    def load_coverage(self):
        """
        An interactive file dialog flow for loading code coverage files.
        """

        #
        # kick off an asynchronous metadata refresh. this collects underlying
        # database metadata while the user will be busy selecting coverage files.
        #
        # the collected metadata enables the director to process, map, and
        # manipulate loaded coverage data in a performant, asynchronous manner.
        #

        future = self.director.metadata.refresh(progress_callback=metadata_progress)

        #
        # prompt the user with a QtFileDialog so that they can select any
        # number of coverage files to load at once.
        #
        # if no files are selected, we abort the coverage loading process.
        #

        filenames = self._select_coverage_files()
        if not filenames:
            return

        #
        # load the selected coverage files from disk
        #

        coverage_data = self._load_coverage_files(filenames)

        #
        # refresh the theme aware color palette for lighthouse
        #

        self.palette.refresh_colors()

        #
        # to continue any further, we need the database metadata. hopefully
        # it has finished with its asynchronous collection, otherwise we will
        # block until it completes. the user will be shown a progress dialog.
        #

        idaapi.show_wait_box("Building database metadata...")
        await_future(future)

        #
        # at this point the metadata caching is guaranteed to be complete.
        # the coverage data has been loaded and is ready for mapping.
        #

        idaapi.replace_wait_box("Normalizing and mapping coverage data...")

        #
        # TODO:
        #
        #   I do not hold great confidence in this code yet, so let's wrap
        #   this in a try/catch so the user doesn't get stuck with a wait
        #   box they can't close should things go poorly ;P
        #

        # start a batch coverage data load for better performance
        self.director.start_batch()

        try:

            for i, data in enumerate(coverage_data):

                # notify the user of what we're doing
                idaapi.replace_wait_box(
                    "Normalizing and mapping coverage %u/%u" % (i, len(coverage_data))
                )

                # normalize coverage data to the database
                name = os.path.basename(data.filepath)
                addresses = self._normalize_coverage(data, self.director.metadata)

                # enlighten the coverage director to this new runtime data
                self.director.add_coverage(name, addresses)

            # select the 'first' coverage file loaded
            self.director.select_coverage(self.director.coverage_names[0])

            # all done, hide the IDA wait box
            idaapi.hide_wait_box()

        # 'something happened :('
        except Exception as e:
            self.director.end_batch()
            idaapi.hide_wait_box()
            lmsg("Failed to load coverage:")
            lmsg("- %s" % e)
            logger.exception(e)
            return

        # collapse the batch job, computing the final aggregate director set
        self.director.end_batch()

        # print a success message to the output window
        lmsg("loaded %u coverage file(s)..." % len(coverage_data))

        # show the coverage overview
        self.open_coverage_overview()

    def open_coverage_overview(self):
        """
        Open the 'Coverage Overview' dialog.
        """
        self._ui_coverage_overview = CoverageOverview(self.director)
        self._ui_coverage_overview.show()

    def _select_coverage_files(self):
        """
        Open the 'Load Code Coverage' dialog and capture file selections.
        """

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtWidgets.QFileDialog(None, 'Open Code Coverage File(s)')
        file_dialog.setFileMode(QtWidgets.QFileDialog.ExistingFiles)

        # prompt the user with the file dialog, and await filename(s)
        filenames, _ = file_dialog.getOpenFileNames()

        # log the captured (selected) filenames from the dialog
        logger.debug("Captured filenames from file dialog:")
        logger.debug(filenames)

        # return the captured filenames
        return filenames

    #--------------------------------------------------------------------------
    # Misc
    #--------------------------------------------------------------------------

    def _load_coverage_files(self, filenames):
        """
        Load multiple code coverage files from disk.
        """
        return [self._load_coverage_file(filename) for filename in filenames]

    def _load_coverage_file(self, filename):
        """
        Load a single code coverage file from disk.

        TODO: Add other formats. Only drcov logs supported for now.
        """
        return DrcovData(filename)

    def _normalize_coverage(self, coverage_data, metadata):
        """
        Normalize loaded coverage data to the database metadata.

        TODO:

          This will probably be moved out and turn into a layer for each unique
          lighthouse coverage parser/loader to implement.

          for example, this effectively translate the DrcovData log to a more
          general / universal format for the director.

        """

        # extract the coverage relevant to this IDB (well, the root binary)
        root_filename   = idaapi.get_root_filename()
        coverage_blocks = coverage_data.filter_by_module(root_filename)

        # rebase the basic blocks
        base = idaapi.get_imagebase()
        rebased_blocks = rebase_blocks(base, coverage_blocks)

        # coalesce the blocks into larger contiguous blobs
        condensed_blocks = coalesce_blocks(rebased_blocks)

        # flatten the blobs into individual instructions or addresses
        return metadata.flatten_blocks(condensed_blocks)

