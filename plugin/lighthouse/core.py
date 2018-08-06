import os
import logging

from lighthouse.ui import CoverageOverview
from lighthouse.util import *
from lighthouse.util.qt import *
from lighthouse.util.disassembler import disassembler
from lighthouse.util.disassembler.ui import *

from lighthouse.parsers import DrcovData
from lighthouse.palette import LighthousePalette
from lighthouse.painting import CoveragePainter
from lighthouse.director import CoverageDirector
from lighthouse.coverage import DatabaseCoverage
from lighthouse.metadata import DatabaseMetadata, metadata_progress

logger = logging.getLogger("Lighthouse.Core")

#------------------------------------------------------------------------------
# Plugin Metadata
#------------------------------------------------------------------------------

PLUGIN_VERSION = "0.7.2"
AUTHORS        = "Markus Gaasedelen"
DATE           = "2018"

#------------------------------------------------------------------------------
# Lighthouse Core
#------------------------------------------------------------------------------

class Lighthouse(object):

    #--------------------------------------------------------------------------
    # Initialization
    #--------------------------------------------------------------------------

    def load(self):
        """
        Initialize & integrate the plugin into IDA.
        """
        self._init()
        self._install_ui()

        # plugin loaded successfully, print the Lighthouse banner
        self.print_banner()
        logger.info("Successfully loaded plugin")

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

        # the directory to start the coverage file dialog in
        self._last_directory = None

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

    def unload(self):
        """
        Cleanup & uninstall the plugin from IDA.
        """
        self._uninstall_ui()
        self._cleanup()

        logger.info("-"*75)
        logger.info("Plugin terminated")

    def _cleanup(self):
        """
        IDB closing event, last chance to spin down threaded workers.
        """
        self.painter.terminate()
        self.director.terminate()

    #--------------------------------------------------------------------------
    # UI - Integration (Internal)
    #--------------------------------------------------------------------------

    def _install_ui(self):
        """
        Initialize & integrate all UI elements.
        """
        self._install_load_file()
        self._install_load_batch()
        self._install_open_coverage_overview()

    def _uninstall_ui(self):
        """
        Cleanup & uninstall the plugin UI from IDA.
        """
        self._uninstall_open_coverage_overview()
        self._uninstall_load_batch()
        self._uninstall_load_file()

    def _install_load_file(self):
        """
        Install the 'File->Load->Code coverage file...' menu entry.
        """
        raise NotImplementedError("_install_load_file")

    def _install_load_batch(self):
        """
        Install the 'File->Load->Code coverage batch...' menu entry.
        """
        raise NotImplementedError("_install_load_batch")

    def _install_open_coverage_overview(self):
        """
        Install the 'View->Open subviews->Coverage Overview' menu entry.
        """
        raise NotImplementedError("_install_open_coverage_overview")

    def _uninstall_load_file(self):
        """
        Remove the 'File->Load file->Code coverage file...' menu entry.
        """
        raise NotImplementedError("_uninstall_load_file")

    def _uninstall_load_batch(self):
        """
        Remove the 'File->Load file->Code coverage batch...' menu entry.
        """
        raise NotImplementedError("_uninstall_load_batch")

    def _uninstall_open_coverage_overview(self):
        """
        Remove the 'View->Open subviews->Coverage Overview' menu entry.
        """
        raise NotImplementedError("_uninstall_open_coverage_overview")

    #--------------------------------------------------------------------------
    # UI - Actions (Public)
    #--------------------------------------------------------------------------

    def open_coverage_overview(self):
        """
        Open the 'Coverage Overview' dialog.
        """
        try:
            self.palette.refresh_colors()

            # the coverage overview is already open & visible, simply refresh it
            if self._ui_coverage_overview and self._ui_coverage_overview.isVisible():
                self._ui_coverage_overview.refresh()
                return

            # create a new coverage overview if there is not one visible
            self._ui_coverage_overview = CoverageOverview(self.director)
            self._ui_coverage_overview.show()
        except Exception as e:
            logger.exception(e)

    def interactive_load_batch(self):
        """
        Interactive loading & aggregation of coverage files.
        """
        self.palette.refresh_colors()

        #
        # kick off an asynchronous metadata refresh. this collects underlying
        # database metadata while the user will be busy selecting coverage files.
        #

        future = self.director.refresh_metadata(progress_callback=metadata_progress)

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

        show_wait_box("Building database metadata...")
        await_future(future)

        # aggregate all the selected files into one new coverage set
        new_coverage = self._aggregate_batch(loaded_files)

        # inject the the aggregated coverage set
        replace_wait_box("Mapping coverage...")
        self.director.create_coverage(coverage_name, new_coverage.data)

        # select the newly created batch coverage
        replace_wait_box("Selecting coverage...")
        self.director.select_coverage(coverage_name)

        # all done, hide the IDA wait box
        hide_wait_box()
        lmsg("Successfully loaded batch %s..." % coverage_name)

        # show the coverage overview
        self.open_coverage_overview()

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

        future = self.director.refresh_metadata(progress_callback=metadata_progress)

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

        show_wait_box("Building database metadata...")
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
            replace_wait_box(
                "Normalizing and mapping coverage %u/%u" % (i, len(loaded_files))
            )

            # normalize coverage data to the open database
            try:
                addresses = normalize_coverage(data, self.director.metadata)
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

        replace_wait_box("Recomputing coverage aggregate...")
        self.director.resume_aggregation()

        # if nothing was mapped, then there's nothing else to do
        if not created_coverage:
            lmsg("No coverage files could be mapped...")
            hide_wait_box()
            return

        #
        # select one (the first) of the newly loaded coverage file(s)
        #

        show_wait_box("Selecting coverage...")
        self.director.select_coverage(created_coverage[0])

        # all done, hide the IDA wait box
        hide_wait_box()
        lmsg("Successfully loaded %u coverage file(s)..." % len(created_coverage))

        # show the coverage overview
        self.open_coverage_overview() # TODO: uncomment once UI working in binja

    #--------------------------------------------------------------------------
    # Internal
    #--------------------------------------------------------------------------

    def _aggregate_batch(self, loaded_files):
        """
        Aggregate the given loaded_files data into a single coverage object.
        """
        show_wait_box("Aggregating coverage batch...")

        # create a new coverage set to manually aggregate data into
        coverage = DatabaseCoverage({}, self.palette)

        #
        # loop through the coverage data we have loaded from disk, and begin
        # the normalization process to translate / filter / flatten it for
        # insertion into the director (as a list of instruction addresses)
        #

        for i, data in enumerate(loaded_files, 1):

            # keep the user informed about our progress while loading coverage
            show_wait_box(
                "Aggregating batch data %u/%u" % (i, len(loaded_files))
            )

            # normalize coverage data to the open database
            try:
                addresses = normalize_coverage(data, self.director.metadata)

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

    def _select_coverage_files(self):
        """
        Internal - prompt a file selection dialog, returning file selections
        """
        if not self._last_directory:
            self._last_directory = disassembler.get_database_directory()

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

    def _select_and_load_coverage_files(self):
        """
        Internal - prompt file dialog, and load selected coverage data.

        Returns a list of DrcovData objects, parsed from disk.
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

        #
        # load the selected coverage files from disk and return their data
        # as a list of DrcovData objects
        #

        return load_coverage_files(filenames)

#------------------------------------------------------------------------------
# Util
#------------------------------------------------------------------------------

def load_coverage_files(filenames):
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
            coverage_data = DrcovData(filename)

        # catch all for parse errors / bad input / malformed files
        except Exception as e:
            lmsg("Failed to load coverage %s" % filename)
            lmsg(" - Error: %s" % str(e))
            logger.exception(" - Traceback:")
            continue

        # save the loaded coverage data to the output list
        loaded_coverage.append(coverage_data)

    # return all the succesfully loaded coverage files
    return loaded_coverage

def normalize_coverage(coverage_data, metadata):
    """
    Normalize loaded DrCov data to the database metadata.
    """

    # extract the coverage relevant to this IDB (well, the root binary)
    root_filename   = disassembler.get_root_filename()
    coverage_blocks = coverage_data.get_blocks_by_module(root_filename)

    # rebase the basic blocks
    base = disassembler.get_imagebase()
    rebased_blocks = rebase_blocks(base, coverage_blocks)

    # coalesce the blocks into larger contiguous blobs
    condensed_blocks = coalesce_blocks(rebased_blocks)

    # flatten the blobs into individual instructions or addresses
    return metadata.flatten_blocks(condensed_blocks)
