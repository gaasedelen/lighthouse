import os
import abc
import logging

from lighthouse.ui import CoverageOverview, CoverageXref
from lighthouse.util import lmsg
from lighthouse.util.qt import *
from lighthouse.util.disassembler import disassembler

from lighthouse.palette import LighthousePalette
from lighthouse.painting import CoveragePainter
from lighthouse.director import CoverageDirector
from lighthouse.coverage import DatabaseCoverage
from lighthouse.metadata import DatabaseMetadata, metadata_progress
from lighthouse.exceptions import *

logger = logging.getLogger("Lighthouse.Core")

#------------------------------------------------------------------------------
# Plugin Metadata
#------------------------------------------------------------------------------

PLUGIN_VERSION = "0.8.4-DEV"
AUTHORS        = "Markus Gaasedelen"
DATE           = "2019"

#------------------------------------------------------------------------------
# Lighthouse Plugin Core
#------------------------------------------------------------------------------

class Lighthouse(object):
    __metaclass__ = abc.ABCMeta

    #--------------------------------------------------------------------------
    # Initialization
    #--------------------------------------------------------------------------

    def load(self):
        """
        Load the plugin, and integrate its UI into the disassembler.
        """
        self._init()
        self._install_ui()

        # plugin loaded successfully, print the plugin banner
        self.print_banner()
        logger.info("Successfully loaded plugin")

    def _init(self):
        """
        Initialize the core components of the plugin.
        """

        # the database metadata cache
        self.metadata = DatabaseMetadata()

        # the plugin color palette
        self.palette = LighthousePalette()

        # the coverage engine
        self.director = CoverageDirector(self.metadata, self.palette)

        # the coverage painter
        self.painter = CoveragePainter(self.director, self.palette)

        # the coverage overview widget
        self._ui_coverage_overview = None

        # the directory to start the coverage file dialog in
        self._last_directory = None

        # a timed callback for lighthouse to check for certain state changes
        self._scheduled = QtCore.QTimer()
        self._scheduled.timeout.connect(self.scheduled)
        #self._scheduled.start(1000) # TODO: re-enable once more testing is done...

    def print_banner(self):
        """
        Print the plugin banner.
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
        Unload the plugin, and remove any UI integrations.
        """
        self._uninstall_ui()
        self._cleanup()

        logger.info("-"*75)
        logger.info("Plugin terminated")

    def _cleanup(self):
        """
        Spin down any lingering core components before plugin unload.
        """
        self._scheduled.stop()
        self.painter.terminate()
        self.director.terminate()
        self.metadata.terminate()

    #--------------------------------------------------------------------------
    # UI Integration (Internal)
    #--------------------------------------------------------------------------

    def _install_ui(self):
        """
        Initialize & integrate all plugin UI elements.
        """
        self._install_load_file()
        self._install_load_batch()
        self._install_open_coverage_xref()
        self._install_open_coverage_overview()

    def _uninstall_ui(self):
        """
        Cleanup & remove all plugin UI integrations.
        """
        self._uninstall_open_coverage_overview()
        self._uninstall_open_coverage_xref()
        self._uninstall_load_batch()
        self._uninstall_load_file()

    @abc.abstractmethod
    def _install_load_file(self):
        """
        Install the 'File->Load->Code coverage file...' menu entry.
        """
        pass

    @abc.abstractmethod
    def _install_load_batch(self):
        """
        Install the 'File->Load->Code coverage batch...' menu entry.
        """
        pass

    @abc.abstractmethod
    def _install_open_coverage_xref(self):
        """
        Install the right click 'Coverage Xref' context menu entry.
        """
        pass

    @abc.abstractmethod
    def _install_open_coverage_overview(self):
        """
        Install the 'View->Open subviews->Coverage Overview' menu entry.
        """
        pass

    @abc.abstractmethod
    def _uninstall_load_file(self):
        """
        Remove the 'File->Load file->Code coverage file...' menu entry.
        """
        pass

    @abc.abstractmethod
    def _uninstall_load_batch(self):
        """
        Remove the 'File->Load file->Code coverage batch...' menu entry.
        """
        pass

    @abc.abstractmethod
    def _uninstall_open_coverage_xref(self):
        """
        Remove the right click 'Coverage Xref' context menu entry.
        """
        pass

    @abc.abstractmethod
    def _uninstall_open_coverage_overview(self):
        """
        Remove the 'View->Open subviews->Coverage Overview' menu entry.
        """
        pass

    #--------------------------------------------------------------------------
    # UI Actions (Public)
    #--------------------------------------------------------------------------

    def open_coverage_overview(self):
        """
        Open the dockable 'Coverage Overview' dialog.
        """
        self.palette.refresh_colors()

        # the coverage overview is already open & visible, simply refresh it
        if self._ui_coverage_overview and self._ui_coverage_overview.isVisible():
            self._ui_coverage_overview.refresh()
            return

        # create a new coverage overview if there is not one visible
        self._ui_coverage_overview = CoverageOverview(self)
        if disassembler.NAME == "CUTTER":
            self._ui_coverage_overview.setmain(disassembler.main)
        self._ui_coverage_overview.show()

    def open_coverage_xref(self, address):
        """
        Open the 'Coverage Xref' dialog for a given address.
        """

        # show the coverage xref dialog
        dialog = CoverageXref(self.director, address)
        if not dialog.exec_():
            return

        # activate the user selected xref (if one was double clicked)
        if dialog.selected_coverage:
            self.director.select_coverage(dialog.selected_coverage)
            return

        # load a coverage file from disk
        disassembler.show_wait_box("Loading coverage from disk...")
        created_coverage, errors = self.director.load_coverage_files(
            [dialog.selected_filepath],
            disassembler.replace_wait_box
        )

        # TODO rough...
        if not created_coverage:
            lmsg("No coverage files could be loaded...")
            disassembler.hide_wait_box()
            warn_errors(errors)
            return

        disassembler.replace_wait_box("Selecting coverage...")
        self.director.select_coverage(created_coverage[0].name)
        disassembler.hide_wait_box()

    def interactive_load_batch(self):
        """
        Perform the user-interactive loading of a coverage batch.
        """
        self.palette.refresh_colors()

        #
        # kick off an asynchronous metadata refresh. this will run in the
        # background while the user is selecting which coverage files to load
        #

        future = self.metadata.refresh_async(progress_callback=metadata_progress)

        #
        # we will now prompt the user with an interactive file dialog so they
        # can select the coverage files they would like to load from disk
        #

        filepaths = self._select_coverage_files()
        if not filepaths:
            self.director.metadata.abort_refresh()
            return

        # prompt the user to name the new coverage aggregate
        default_name = "BATCH_%s" % self.director.peek_shorthand()
        ok, batch_name = prompt_string(
            "Batch Name:",
            "Please enter a name for this coverage",
            default_name
        )

        #
        # if user didn't enter a name for the batch (or hit cancel) we should
        # abort the loading process...
        #

        if not (ok and batch_name):
            lmsg("User failed to enter a name for the batch coverage...")
            self.director.metadata.abort_refresh()
            return

        #
        # to begin mapping the loaded coverage data, we require that the
        # asynchronous database metadata refresh has completed. if it is
        # not done yet, we will block here until it completes.
        #
        # a progress dialog depicts the work remaining in the refresh
        #

        disassembler.show_wait_box("Building database metadata...")
        await_future(future)

        #
        # now that the database metadata is available, we can use the director
        # to normalize and condense (aggregate) all the coverage data
        #

        disassembler.replace_wait_box("Loading coverage from disk...")
        batch_coverage, errors = self.director.load_coverage_batch(
            filepaths,
            batch_name,
            disassembler.replace_wait_box
        )

        # if batch creation fails...
        if not batch_coverage:
            lmsg("Creation of batch '%s' failed..." % batch_name)
            disassembler.hide_wait_box()
            warn_errors(errors)
            return

        # select the newly created batch coverage
        disassembler.replace_wait_box("Selecting coverage...")
        self.director.select_coverage(batch_name)

        # all done! pop the coverage overview to show the user their results
        disassembler.hide_wait_box()
        lmsg("Successfully loaded batch %s..." % batch_name)
        self.open_coverage_overview()

        # finally, emit any notable issues that occurred during load
        warn_errors(errors)

    def interactive_load_file(self):
        """
        Perform the user-interactive loading of individual coverage files.
        """
        self.palette.refresh_colors()

        #
        # kick off an asynchronous metadata refresh. this will run in the
        # background while the user is selecting which coverage files to load
        #

        future = self.metadata.refresh_async(progress_callback=metadata_progress)

        #
        # we will now prompt the user with an interactive file dialog so they
        # can select the coverage files they would like to load from disk
        #

        filenames = self._select_coverage_files()
        if not filenames:
            self.director.metadata.abort_refresh()
            return

        #
        # to begin mapping the loaded coverage data, we require that the
        # asynchronous database metadata refresh has completed. if it is
        # not done yet, we will block here until it completes.
        #
        # a progress dialog depicts the work remaining in the refresh
        #

        disassembler.show_wait_box("Building database metadata...")
        await_future(future)

        #
        # now that the database metadata is available, we can use the director
        # to load and normalize the selected coverage files
        #

        disassembler.replace_wait_box("Loading coverage from disk...")
        created_coverage, errors = self.director.load_coverage_files(filenames, disassembler.replace_wait_box)

        #
        # if the director failed to map any coverage, the user probably
        # provided bad files. emit any warnings and bail...
        #

        if not created_coverage:
            lmsg("No coverage files could be loaded...")
            disassembler.hide_wait_box()
            warn_errors(errors)
            return

        #
        # activate the first of the newly loaded coverage file(s). this is the
        # one that will be visible in the coverage overview once opened
        #

        disassembler.replace_wait_box("Selecting coverage...")
        self.director.select_coverage(created_coverage[0].name)

        # all done! pop the coverage overview to show the user their results
        disassembler.hide_wait_box()
        lmsg("Successfully loaded %u coverage file(s)..." % len(created_coverage))
        self.open_coverage_overview()

        # finally, emit any notable issues that occurred during load
        warn_errors(errors)

    def _select_coverage_files(self):
        """
        Prompt a file selection dialog, returning file selections.

        NOTE: This saves & reuses the last known directory for subsequent uses.
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
        for name in filenames:
            logger.debug(" - %s" % name)

        # return the captured filenames
        return filenames

    #--------------------------------------------------------------------------
    # Scheduled
    #--------------------------------------------------------------------------

    @disassembler.execute_read
    def scheduled(self):
        metadata = self.director.metadata

        # get current imagebase
        base = disassembler.get_imagebase()
        lmsg("Imagebase: 0x%08x" % base)

        # detect an image rebase
        if (metadata.cached and base != metadata.imagebase) and not disassembler.busy:
            lmsg("Image rebase detected, rebasing Lighthouse metadata...")
            self.director.refresh()

        # schedule the next update
        self._scheduled.start(1000)
