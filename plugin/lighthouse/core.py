import os
import abc
import logging

from lighthouse.ui import CoverageOverview
from lighthouse.util import lmsg
from lighthouse.util.qt import *
from lighthouse.util.disassembler import disassembler

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

PLUGIN_VERSION = "0.8.3"
AUTHORS        = "Markus Gaasedelen"
DATE           = "2018"

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

        # the plugin's color palette
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
        self.painter.terminate()
        self.director.terminate()

    #--------------------------------------------------------------------------
    # UI Integration (Internal)
    #--------------------------------------------------------------------------

    def _install_ui(self):
        """
        Initialize & integrate all plugin UI elements.
        """
        self._install_load_file()
        self._install_load_batch()
        self._install_open_coverage_overview()

    def _uninstall_ui(self):
        """
        Cleanup & remove all plugin UI integrations.
        """
        self._uninstall_open_coverage_overview()
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
        self._ui_coverage_overview.show()

    def interactive_load_batch(self):
        """
        Perform the user-interactive loading of a coverage batch.
        """
        self.palette.refresh_colors()

        #
        # kick off an asynchronous metadata refresh. this will run in the
        # background while the user is selecting which coverage files to load
        #

        future = self.director.refresh_metadata(
            progress_callback=metadata_progress
        )

        #
        # we will now prompt the user with an interactive file dialog so they
        # can select the coverage files they would like to load from disk
        #

        filenames = self._select_coverage_files()

        #
        # load the selected coverage files from disk (if any), returning a list
        # of loaded DrcovData objects (which contain coverage data)
        #

        drcov_list = load_coverage_files(filenames)
        if not drcov_list:
            self.director.metadata.abort_refresh()
            return

        # prompt the user to name the new coverage aggregate
        default_name = "BATCH_%s" % self.director.peek_shorthand()
        ok, coverage_name = prompt_string(
            "Batch Name:",
            "Please enter a name for this coverage",
            default_name
        )

        #
        # if user didn't enter a name for the batch (or hit cancel) we should
        # abort the loading process...
        #

        if not (ok and coverage_name):
            lmsg("User failed to enter a name for the loaded batch...")
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

        new_coverage, errors = self.director.aggregate_drcov_batch(drcov_list)

        #
        # finally, we can inject the aggregated coverage data into the
        # director under the user specified batch name
        #

        disassembler.replace_wait_box("Mapping coverage...")
        self.director.create_coverage(coverage_name, new_coverage.data)

        # select the newly created batch coverage
        disassembler.replace_wait_box("Selecting coverage...")
        self.director.select_coverage(coverage_name)

        # all done! pop the coverage overview to show the user their results
        disassembler.hide_wait_box()
        lmsg("Successfully loaded batch %s..." % coverage_name)
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

        future = self.director.refresh_metadata(
            progress_callback=metadata_progress
        )

        #
        # we will now prompt the user with an interactive file dialog so they
        # can select the coverage files they would like to load from disk
        #

        filenames = self._select_coverage_files()

        #
        # load the selected coverage files from disk (if any), returning a list
        # of loaded DrcovData objects (which contain coverage data)
        #

        disassembler.show_wait_box("Loading coverage from disk...")
        drcov_list = load_coverage_files(filenames)
        if not drcov_list:
            disassembler.hide_wait_box()
            self.director.metadata.abort_refresh()
            return

        #
        # to begin mapping the loaded coverage data, we require that the
        # asynchronous database metadata refresh has completed. if it is
        # not done yet, we will block here until it completes.
        #
        # a progress dialog depicts the work remaining in the refresh
        #

        disassembler.replace_wait_box("Building database metadata...")
        await_future(future)

        # insert the loaded drcov data objects into the director
        created_coverage, errors = self.director.create_coverage_from_drcov_list(drcov_list)

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
        self.director.select_coverage(created_coverage[0])

        # all done! pop the coverage overview to show the user their results
        disassembler.hide_wait_box()
        lmsg("Successfully loaded %u coverage file(s)..." % len(created_coverage))
        self.open_coverage_overview()

        # finally, emit any notable issues that occurred during load
        warn_errors(errors)

    #--------------------------------------------------------------------------
    # Internal
    #--------------------------------------------------------------------------

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

    load_failure = False
    for filename in filenames:

        # attempt to load/parse a single coverage data file from disk
        try:
            drcov_data = DrcovData(filename)

        # catch all for parse errors / bad input / malformed files
        except Exception as e:
            lmsg("Failed to load coverage %s" % filename)
            lmsg(" - Error: %s" % str(e))
            logger.exception(" - Traceback:")
            load_failure = True
            continue

        # save the loaded coverage data to the output list
        loaded_coverage.append(drcov_data)

    # warn if we encountered malformed files...
    if load_failure:
        warn_drcov_malformed()

    # return all the successfully loaded coverage files
    return loaded_coverage

#------------------------------------------------------------------------------
# Warnings
#------------------------------------------------------------------------------

def warn_errors(errors):
    """
    Warn the user of any encountered errors with a messagebox.
    """
    seen = []

    for error in errors:
        error_type = error[0]

        # only emit an error once
        if error_type in seen:
            continue

        # emit relevant error messages
        if error_type == CoverageDirector.ERROR_COVERAGE_ABSENT:
            warn_module_missing()
        elif error_type == CoverageDirector.ERROR_COVERAGE_SUSPICIOUS:
            warn_bad_mapping()
        else:
            raise NotImplementedError("UNKNOWN ERROR OCCURRED")

        seen.append(error_type)

def warn_drcov_malformed():
    """
    Display a warning for malformed/unreadable coverage files.
    """
    disassembler.warning(
        "Failed to parse one or more of the selected coverage files!\n\n"
        " Possible reasons:\n"
        " - You selected a file that was *not* a coverage file.\n"
        " - The selected coverage file is malformed or unreadable.\n\n"
        "Please see the disassembler console for more info..."
    )

def warn_module_missing():
    """
    Display a warning for missing coverage data.
    """
    disassembler.warning(
        "No coverage data was extracted from one of the selected files.\n\n"
        " Possible reasons:\n"
        " - You selected a coverage file for the wrong binary.\n"
        " - The name of the executable file used to generate this database\n"
        "    is different than the one you collected coverage against.\n"
        " - Your DBI failed to collect any coverage for this binary.\n\n"
        "Please see the disassembler console for more info..."
    )

def warn_bad_mapping():
    """
    Display a warning for badly mapped coverage data.
    """
    disassembler.warning(
        "One or more of the loaded coverage files appears to be badly mapped.\n\n"
        " Possible reasons:\n"
        " - You selected a coverage file that was collected against a\n"
        "    slightly different version of the binary.\n"
        " - You recorded an application with very abnormal control flow.\n"
        " - The coverage file might be malformed.\n\n"
        "This means that any coverage displayed by Lighthouse is probably\n"
        "wrong, and should be used at your own discretion."
    )

