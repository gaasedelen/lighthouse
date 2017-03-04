import logging

from lighthouse.util import *
from lighthouse.painting import *
from lighthouse.metadata import DatabaseMetadata
from lighthouse.coverage import DatabaseCoverage

logger = logging.getLogger("Lighthouse.Director")

#------------------------------------------------------------------------------
# The Coverage Director
#------------------------------------------------------------------------------

class CoverageDirector(object):
    """

    TODO/NOTE:

      In the long run, I imagine this class will grow to become
      the hub for all coverage data. By the time the coverage reaches
      this hub, it should be in a generic (offset, size) block format.

      This hub will be the data source should a user wish to flip
      between any loaded coverage, or even view metrics on a union of
      the loaded overages.

      As the class sits now, it is minimal and caters to only a single
      source of coverage data.

      # - Databbase/ function / node metadata can be a shared resource
      # - Only coverage changes

    """

    def __init__(self, palette):

        # database metadata cache
        self._database_metadata = None

        # database coverage mappings
        self._database_coverage = {}
        self.coverage_name     = None

        # a user rendered composite of coverage data
        self._composite_coverage = None

        # the color palette
        self._palette = palette

    #----------------------------------------------------------------------
    # Properties
    #----------------------------------------------------------------------

    @property
    def metadata(self):
        return self._database_metadata

    @property
    def coverage(self):
        return self._database_coverage[self.coverage_name]

    @property
    def coverage_names(self):
        return self._database_coverage.iterkeys()

    #----------------------------------------------------------------------
    # Controls
    #----------------------------------------------------------------------

    def select_coverage(self, coverage_name):
        """
        Activate loaded coverage by name.
        """
        logger.debug("Selecting coverage %s" % coverage_name)
        self.coverage_name = coverage_name
        self.paint_coverage()

    def add_coverage(self, coverage_name, coverage_base, coverage_data):
        """
        Add new coverage to the director.
        """
        logger.debug("Adding coverage %s" % coverage_name)

        # initialize a new database-wide coverage object for this data
        new_coverage = DatabaseCoverage(coverage_base, coverage_data, self._palette)

        # map the coverage data using the database metadata
        new_coverage.refresh(self.metadata)

        # coverage creation & mapping complete, looks like we're good. add the
        # new coverage to the director's coverage table and surface it for use.
        self._database_coverage[coverage_name] = new_coverage

    def paint_coverage(self):
        """
        Paint the active coverage to the database.

        TODO: I am not convinced the director should have any of the painting code.
        """
        logger.debug("Painting active coverage")

        #
        # depending on if IDA is using a dark or light theme, we paint
        # coverage with a color that will hopefully keep things readable.
        # determine whether to use a 'dark' or 'light' paint
        #

        bg_color = get_disas_bg_color()
        if bg_color.lightness() > 255.0/2:
            color = self._palette.paint_light
        else:
            color = self._palette.paint_dark

        # color the database based on coverage
        paint_coverage(self.metadata, self.coverage, color)

    def refresh(self):
        """
        Complete refresh of coverage mapping to the active database.
        """
        logger.debug("Refreshing the CoverageDirector")

        # (re)build our knowledge of the underlying database
        self._refresh_database_metadata()

        # (re)map each set of coverage data to the database
        self._refresh_database_coverage()

    #----------------------------------------------------------------------
    # Refresh Internals
    #----------------------------------------------------------------------

    def _refresh_database_metadata(self):
        """
        Refresh the database metadata cache utilized by the director.
        """
        logger.debug("Refreshing database metadata")
        self._database_metadata = DatabaseMetadata()
        # TODO: return metadata delta

    def _refresh_database_coverage(self):
        """
        Refresh the database coverage mappings managed by the director.
        """
        logger.debug("Refreshing database coverage mappings")
        for name, coverage in self._database_coverage.iteritems():
            logger.debug(" - %s" % name)
            coverage.refresh(self.metadata)
