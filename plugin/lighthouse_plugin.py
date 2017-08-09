import os

import idaapi
import idautils

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

PLUGIN_VERSION = "0.5.0"
AUTHORS        = "Markus Gaasedelen"
DATE           = "2017"

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return Lighthouse()

class Lighthouse(idaapi.plugin_t):
    """
    The Lighthouse IDA Plugin.
    """

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_MOD | idaapi.PLUGIN_HIDE
    comment = "Code Coverage Explorer"
    help = ""
    wanted_name = "Lighthouse"
    wanted_hotkey = ""

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
        self._init()
        self._install_ui()

    def _init(self):
        """
        Initialize plugin members.
        """

        # plugin color palette
        self.palette = LighthousePalette()

        # the coverage engine
        self.director = CoverageDirector(self.palette)

        # the coverage painter
        self.painter = CoveragePainter(self.director, self.palette)

        # the coverage overview widget
        self._ui_coverage_overview = None

        # members for the 'Load Code Coverage' menu entry
        self._icon_id_load = idaapi.BADADDR

        # members for the 'Coverage Overview' menu entry
        self._icon_id_overview = idaapi.BADADDR

        # the directory to start the coverage file dialog in
        self._last_directory = idautils.GetIdbDir()

    def _install_ui(self):
        """
        Initialize & integrate all UI elements.
        """

        # install the 'Load Coverage' file dialog
        self._install_load_file_dialog()
        self._install_open_coverage_overview()

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
    # Termination
    #--------------------------------------------------------------------------

    def _uninstall_plugin(self):
        """
        Cleanup & uninstall the plugin from IDA.
        """
        self._uninstall_ui()
        self._cleanup()

    def _uninstall_ui(self):
        """
        Cleanup & uninstall the plugin UI from IDA.
        """
        self._uninstall_open_coverage_overview()
        self._uninstall_load_file_dialog()

    def _cleanup(self):
        """
        Signal threads to exit and wait.
        """
        self.director.terminate()
        self.painter.terminate()

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_LOAD_COVERAGE     = "lighthouse:load_coverage"
    ACTION_COVERAGE_OVERVIEW = "lighthouse:coverage_overview"

    def _install_load_file_dialog(self):
        """
        Install the 'File->Load->Code Coverage File(s)...' menu entry.
        """

        # create a custom IDA icon
        icon_path = plugin_resource(os.path.join("icons", "load.png"))
        icon_data = str(open(icon_path, "rb").read())
        self._icon_id_load = idaapi.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self.ACTION_LOAD_COVERAGE,                # The action name.
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
            self.ACTION_LOAD_COVERAGE,  # The action ID (see above)
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
        icon_path = plugin_resource(os.path.join("icons", "overview.png"))
        icon_data = str(open(icon_path, "rb").read())
        self._icon_id_overview = idaapi.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self.ACTION_COVERAGE_OVERVIEW,            # The action name.
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
            self.ACTION_COVERAGE_OVERVIEW,    # The action ID (see above)
            idaapi.SETMENU_INS             # We want to insert the action before ^
        )
        if not result:
            RuntimeError("Failed action attach to 'View/Open subviews' dropdown")

        logger.info("Installed the 'Coverage Overview' menu entry")

    def _uninstall_load_file_dialog(self):
        """
        Remove the 'File->Load file->Code Coverage File(s)...' menu entry.
        """

        # remove the entry from the File-> menu
        result = idaapi.detach_action_from_menu(
            "File/Load file/",
            self.ACTION_LOAD_COVERAGE
        )
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self.ACTION_LOAD_COVERAGE)
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
            self.ACTION_COVERAGE_OVERVIEW
        )
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self.ACTION_COVERAGE_OVERVIEW)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_overview)
        self._icon_id_overview = idaapi.BADADDR

        logger.info("Uninstalled the 'Coverage Overview' menu entry")

    #--------------------------------------------------------------------------
    # UI - Actions
    #--------------------------------------------------------------------------

    def open_coverage_overview(self):
        """
        Open the 'Coverage Overview' dialog.
        """

        # the coverage overview is already open & visible, simply refresh it
        if self._ui_coverage_overview and self._ui_coverage_overview.visible():
            self._ui_coverage_overview.refresh()
            return

        # create a new coverage overview if there is not one visible
        self._ui_coverage_overview = CoverageOverview(self.director)
        self._ui_coverage_overview.show()

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

        loaded_coverage = self._load_coverage_files(filenames)
        if not loaded_coverage:
            self.director.metadata.abort_refresh()
            return

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
        # the coverage data has been loaded and is ready for mapping and
        # management by the director.
        #

        idaapi.replace_wait_box("Normalizing and mapping coverage data...")

        #
        # start a batch coverage data load for better performance incase we
        # are loading more than one new coverage file / data to the director.
        #

        self.director.start_batch()

        # a list to output the names of successfully mapped coverage files
        mapped_coverage = []

        #
        # loop through the coverage data we have loaded from disk, and begin
        # the normalization process to translate / filter / flatten it for
        # insertion into the director (as a list of instruction addresses)
        #

        for i, data in enumerate(loaded_coverage, 1):

            # keep the user informed about our progress while loading coverage
            idaapi.replace_wait_box("Normalizing and mapping coverage %u/%u" % (i, len(loaded_coverage)))

            # TODO: it would be nice to get rid of this try/catch in the long run
            try:

                # normalize coverage data to the database
                addresses = self._normalize_coverage(data, self.director.metadata)

                # enlighten the coverage director to this new runtime data
                coverage_name = os.path.basename(data.filepath)
                self.director.add_coverage(coverage_name, addresses)

                # if we made it this far, the coverage must have loaded okay...
                mapped_coverage.append(coverage_name)

            except Exception as e:
                lmsg("Failed to map coverage %s" % data.filepath)
                lmsg("- %s" % e)
                logger.exception("Error details:")
                continue

        # collapse the batch job to recompute the director's aggregate coverage set
        self.director.end_batch()

        # select the 'first' coverage file loaded and mapped from this round
        if mapped_coverage:
            self.director.select_coverage(mapped_coverage[0])

        # all done, hide the IDA wait box
        idaapi.hide_wait_box()

        # print a success message to the output window
        lmsg("Successfully loaded %u coverage file(s)..." % len(mapped_coverage))

        # show the coverage overview
        self.open_coverage_overview()

    def _select_coverage_files(self):
        """
        Open the 'Load Code Coverage' dialog and capture file selections.
        """

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtWidgets.QFileDialog(
            None,
            'Open Code Coverage File(s)',
            self._last_directory,
            'All Files (*.*)'
        )
        file_dialog.setFileMode(QtWidgets.QFileDialog.ExistingFiles)

        # prompt the user with the file dialog, and await filename(s)
        filenames, _ = file_dialog.getOpenFileNames()

        #
        # remember the last directory we were in (parsed from a selected file)
        # for the next time the user comes to load coverage files
        #

        if filenames:
            self._last_directory = os.path.dirname(filenames[0]) + os.sep

        # log the captured (selected) filenames from the dialog
        logger.debug("Captured filenames from file dialog:")
        logger.debug('\n - ' + '\n - '.join(filenames))

        # return the captured filenames
        return filenames

    #--------------------------------------------------------------------------
    # Misc
    #--------------------------------------------------------------------------
    #
    #   NOTE / FUTURE / TODO
    #
    #    In my vision for Lighthouse, I always imagined that it would be
    #    able to dynamically detect and load coverage data from a variety of
    #    different coverage sources and formats (DR, PIN, an inst trace, etc)
    #
    #    The dream was that Lighthouse would have a folder of loaders to parse
    #    and normalize their data to the database / loaded executable so that
    #    they can be injected into the director for exploration.
    #
    #    I would still like to do this, but really haven't heard many people
    #    asking for additional coverage source support yet... so this feature
    #    keeps getting pushed back.
    #
    #    ...
    #
    #    In the mean time, we have a few random functions that are hardcoded
    #    here to load DrCov files and normalize them to the current databasae.
    #

    def _load_coverage_files(self, filenames):
        """
        Load multiple code coverage files from disk.
        """
        loaded_coverage = []

        #
        # loop through each of the given filenames and attempt to load/parse
        # their coverage data from disk
        #

        for filename in filenames:

            # attempt to load/parse a single coverage data file from disk
            try:
                coverage_data = self._load_coverage_file(filename)

            # catch all for parse errors / bad input / malformed files
            except Exception as e:
                lmsg("Failed to load coverage %s" % filename)
                logger.exception("Error details:")
                continue

            # save the loaded coverage data to the output list
            loaded_coverage.append(coverage_data)

        # return all the succesfully loaded coverage files
        return loaded_coverage

    def _load_coverage_file(self, filename):
        """
        Load a single code coverage file from disk.
        """
        return DrcovData(filename)

    def _normalize_coverage(self, coverage_data, metadata):
        """
        Normalize loaded DrCov data to the database metadata.
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

