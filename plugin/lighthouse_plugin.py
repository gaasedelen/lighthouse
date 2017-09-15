import os

import idaapi
import idautils

from lighthouse.ui import *
from lighthouse.util import *
from lighthouse.parsers import *
from lighthouse.palette import LighthousePalette
from lighthouse.painting import CoveragePainter
from lighthouse.director import CoverageDirector
from lighthouse.coverage import DatabaseCoverage
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

        # menu entry icons
        self._icon_id_file = idaapi.BADADDR
        self._icon_id_batch = idaapi.BADADDR
        self._icon_id_overview = idaapi.BADADDR

        # the directory to start the coverage file dialog in
        self._last_directory = idautils.GetIdbDir()

    def _install_ui(self):
        """
        Initialize & integrate all UI elements.
        """
        self._install_load_file()
        self._install_load_batch()
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
        self._uninstall_load_batch()
        self._uninstall_load_file()

    def _cleanup(self):
        """
        IDB closing event, last chance to spin down threaded workers.
        """
        self.painter.terminate()
        self.director.terminate()

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_LOAD_FILE         = "lighthouse:load_file"
    ACTION_LOAD_BATCH        = "lighthouse:load_batch"
    ACTION_COVERAGE_OVERVIEW = "lighthouse:coverage_overview"

    def _install_load_file(self):
        """
        Install the 'File->Load->Code coverage file...' menu entry.
        """

        # create a custom IDA icon
        icon_path = plugin_resource(os.path.join("icons", "load.png"))
        icon_data = str(open(icon_path, "rb").read())
        self._icon_id_file = idaapi.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self.ACTION_LOAD_FILE,                     # The action name.
            "~C~ode coverage file...",                 # The action text.
            IDACtxEntry(self.interactive_load_file),   # The action handler.
            None,                                      # Optional: action shortcut
            "Load individual code coverage file(s)",   # Optional: tooltip
            self._icon_id_file                         # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register load_file action with IDA")

        # attach the action to the File-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "File/Load file/",       # Relative path of where to add the action
            self.ACTION_LOAD_FILE,   # The action ID (see above)
            idaapi.SETMENU_APP       # We want to append the action after ^
        )
        if not result:
            RuntimeError("Failed action attach load_file")

        logger.info("Installed the 'Code coverage file' menu entry")

    def _install_load_batch(self):
        """
        Install the 'File->Load->Code coverage batch...' menu entry.
        """

        # create a custom IDA icon
        icon_path = plugin_resource(os.path.join("icons", "batch.png"))
        icon_data = str(open(icon_path, "rb").read())
        self._icon_id_batch = idaapi.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self.ACTION_LOAD_BATCH,                   # The action name.
            "~C~ode coverage batch...",               # The action text.
            IDACtxEntry(self.interactive_load_batch), # The action handler.
            None,                                     # Optional: action shortcut
            "Load and aggregate code coverage files", # Optional: tooltip
            self._icon_id_batch                       # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register load_batch action with IDA")

        # attach the action to the File-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "File/Load file/",          # Relative path of where to add the action
            self.ACTION_LOAD_BATCH,     # The action ID (see above)
            idaapi.SETMENU_APP          # We want to append the action after ^
        )
        if not result:
            RuntimeError("Failed action attach load_batch")

        logger.info("Installed the 'Code coverage batch' menu entry")

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

    def _uninstall_load_file(self):
        """
        Remove the 'File->Load file->Code coverage file...' menu entry.
        """

        # remove the entry from the File-> menu
        result = idaapi.detach_action_from_menu(
            "File/Load file/",
            self.ACTION_LOAD_FILE
        )
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self.ACTION_LOAD_FILE)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_file)
        self._icon_id_file = idaapi.BADADDR

        logger.info("Uninstalled the 'Code coverage file' menu entry")

    def _uninstall_load_batch(self):
        """
        Remove the 'File->Load file->Code coverage batch...' menu entry.
        """

        # remove the entry from the File-> menu
        result = idaapi.detach_action_from_menu(
            "File/Load file/",
            self.ACTION_LOAD_BATCH
        )
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self.ACTION_LOAD_BATCH)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_batch)
        self._icon_id_batch = idaapi.BADADDR

        logger.info("Uninstalled the 'Code coverage batch' menu entry")

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
        self.palette.refresh_colors()

        # the coverage overview is already open & visible, simply refresh it
        if self._ui_coverage_overview and self._ui_coverage_overview.isVisible():
            self._ui_coverage_overview.refresh()
            return

        # create a new coverage overview if there is not one visible
        self._ui_coverage_overview = CoverageOverview(self.director)
        self._ui_coverage_overview.show()

    def interactive_load_batch(self):
        """
        Interactive loading & aggregation of coverage files.
        """
        self.palette.refresh_colors()

        #
        # kick off an asynchronous metadata refresh. this collects underlying
        # database metadata while the user will be busy selecting coverage files.
        #

        future = self.director.metadata.refresh(progress_callback=metadata_progress)

        #
        # we will now prompt the user with an interactive file dialog so they
        # can select the coverage files they would like to load from disk.
        #

        loaded_files = self._select_and_load_coverage_files()

        # if no valid coveragee files were selected (and loaded), bail
        if not loaded_files:
            self.director.metadata.abort_refresh()
            return

        # prompt the user to name the new coverage aggregate
        default_name = "BATCH_%s" % self.director.peek_shorthand()
        ok, coverage_name = prompt_string(
            "Batch Name:",
            "Please enter a name for this coverage",
            default_name
        )

        # if user didn't enter a name for the batch, or hit cancel, we abort
        if not (ok and coverage_name):
            lmsg("Aborting batch load...")
            return

        #
        # to continue any further, we need the database metadata. hopefully
        # it has finished with its asynchronous collection, otherwise we will
        # block until it completes. the user will be shown a progress dialog.
        #

        idaapi.show_wait_box("Building database metadata...")
        await_future(future)

        # aggregate all the selected files into one new coverage set
        new_coverage = self._aggregate_batch(loaded_files)

        # inject the the aggregated coverage set
        idaapi.replace_wait_box("Mapping coverage...")
        self.director.create_coverage(coverage_name, new_coverage.data)

        # select the newly created batch coverage
        idaapi.replace_wait_box("Selecting coverage...")
        self.director.select_coverage(coverage_name)

        # all done, hide the IDA wait box
        idaapi.hide_wait_box()
        lmsg("Successfully loaded batch %s..." % coverage_name)

        # show the coverage overview
        self.open_coverage_overview()

    def _aggregate_batch(self, loaded_files):
        """
        Aggregate the given loaded_files data into a single coverage object.
        """
        idaapi.replace_wait_box("Aggregating coverage batch...")

        # create a new coverage set to manually aggregate data into
        coverage = DatabaseCoverage({}, self.palette)

        #
        # loop through the coverage data we have loaded from disk, and begin
        # the normalization process to translate / filter / flatten it for
        # insertion into the director (as a list of instruction addresses)
        #

        for i, data in enumerate(loaded_files, 1):

            # keep the user informed about our progress while loading coverage
            idaapi.replace_wait_box(
                "Aggregating batch data %u/%u" % (i, len(loaded_files))
            )

            # normalize coverage data to the open database
            try:
                addresses = self._normalize_coverage(data, self.director.metadata)

            # normalization failed, print & log it
            except Exception as e:
                lmsg("Failed to map coverage %s" % data.filepath)
                lmsg("- %s" % e)
                logger.exception("Error details:")
                continue

            # aggregate the addresses into the output coverage object
            coverage.add_addresses(addresses, False)

        # return the created coverage name
        return coverage

    def interactive_load_file(self):
        """
        Interactive loading of individual coverage files.
        """
        self.palette.refresh_colors()
        created_coverage = []

        #
        # kick off an asynchronous metadata refresh. this collects underlying
        # database metadata while the user will be busy selecting coverage files.
        #

        future = self.director.metadata.refresh(progress_callback=metadata_progress)

        #
        # we will now prompt the user with an interactive file dialog so they
        # can select the coverage files they would like to load from disk.
        #

        loaded_files = self._select_and_load_coverage_files()

        # if no valid coveragee files were selected (and loaded), bail
        if not loaded_files:
            self.director.metadata.abort_refresh()
            return

        #
        # to continue any further, we need the database metadata. hopefully
        # it has finished with its asynchronous collection, otherwise we will
        # block until it completes. the user will be shown a progress dialog.
        #

        idaapi.show_wait_box("Building database metadata...")
        await_future(future)

        #
        # stop the director's aggregate from updating. this is in the interest
        # of better performance when loading more than one new coverage set
        # into the director.
        #

        self.director.suspend_aggregation()

        #
        # loop through the coverage data we have loaded from disk, and begin
        # the normalization process to translate / filter / flatten its blocks
        # into a generic format the director can understand (a list of addresses)
        #

        for i, data in enumerate(loaded_files, 1):

            # keep the user informed about our progress while loading coverage
            idaapi.replace_wait_box(
                "Normalizing and mapping coverage %u/%u" % (i, len(loaded_files))
            )

            # normalize coverage data to the open database
            try:
                addresses = self._normalize_coverage(data, self.director.metadata)
            except Exception as e:
                lmsg("Failed to map coverage %s" % data.filepath)
                lmsg("- %s" % e)
                logger.exception("Error details:")
                continue

            #
            # ask the director to create and track a new coverage set from
            # the normalized coverage data we provide
            #

            coverage_name = os.path.basename(data.filepath)
            self.director.create_coverage(coverage_name, addresses)

            # save the coverage name to the list of succesful loads
            created_coverage.append(coverage_name)

        #
        # resume the director's aggregation capabilities, triggering an update
        # to recompute the aggregate with the newly loaded coverage
        #

        idaapi.replace_wait_box("Recomputing coverage aggregate...")
        self.director.resume_aggregation()

        # if nothing was mapped, then there's nothing else to do
        if not created_coverage:
            lmsg("No coverage files could be mapped...")
            idaapi.hide_wait_box()
            return

        #
        # select one (the first) of the newly loaded coverage file(s)
        #

        idaapi.replace_wait_box("Selecting coverage...")
        self.director.select_coverage(created_coverage[0])

        # all done, hide the IDA wait box
        idaapi.hide_wait_box()
        lmsg("Successfully loaded %u coverage file(s)..." % len(created_coverage))

        # show the coverage overview
        self.open_coverage_overview()

    def _select_and_load_coverage_files(self):
        """
        Interactive coverage file selection.
        """

        #
        # prompt the user with a QtFileDialog so that they can select any
        # number of coverage files to load at once.
        #
        # if no files are selected, we abort the coverage loading process.
        #

        filenames = self._select_coverage_files()
        if not filenames:
            return None

        # load the selected coverage files from disk and return them
        return self._load_coverage_files(filenames)

    def _select_coverage_files(self):
        """
        Open the 'Load Code Coverage' dialog and capture file selections.
        """

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtWidgets.QFileDialog(
            None,
            'Open code coverage file',
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
