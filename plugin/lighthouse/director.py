import logging

from lighthouse.util import *
from lighthouse.painting import *
from lighthouse.metadata import DatabaseMetadata, MetadataDelta
from lighthouse.coverage import DatabaseCoverage

logger = logging.getLogger("Lighthouse.Director")

#------------------------------------------------------------------------------
# The Coverage Director
#------------------------------------------------------------------------------

class CoverageDirector(object):
    """
    The Coverage Director manages loaded coverage.

    NOTE/TODO:

      The role of the director is critical in building the culminating
      experience envisioned for Lighthouse. As of now (v0.2.0) its scope
      and functionality is limited to simply hosting and switching between
      the loaded coverage data sets.

      There are more interesting things to come.


    #--------------------------------------------------------------------------

    --[ Composing

    TODO: coming soon

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
        """
        The active database metadata cache.
        """
        return self._database_metadata

    @property
    def coverage(self):
        """
        The active database coverage.
        """
        try:
            return self._database_coverage[self.coverage_name]
        except KeyError as e:
            return None

    @property
    def coverage_names(self):
        """
        The names of loaded coverage data.
        """
        return self._database_coverage.iterkeys()

    #----------------------------------------------------------------------
    # Controls
    #----------------------------------------------------------------------

    def select_coverage(self, coverage_name):
        """
        Activate loaded coverage by name.
        """
        logger.debug("Selecting coverage %s" % coverage_name)
        self.unpaint_coverage() # TODO: this is a temporary implementation
        self.coverage_name = coverage_name
        self.paint_coverage()

    def add_coverage(self, coverage_name, coverage_base, coverage_data):
        """
        Add new coverage to the director.
        """
        logger.debug("Adding coverage %s" % coverage_name)

        # ensure the palette colors are up to date before use
        self._palette.refresh_colors()

        # initialize a new database-wide coverage object for this data
        new_coverage = DatabaseCoverage(coverage_base, coverage_data, self._palette)

        # map the coverage data using the database metadata
        new_coverage.refresh(self.metadata)

        # coverage creation & mapping complete, looks like we're good. add the
        # new coverage to the director's coverage table and surface it for use.
        self._database_coverage[coverage_name] = new_coverage

    def refresh(self):
        """
        Complete refresh of coverage mapping to the active database.
        """
        logger.debug("Refreshing the CoverageDirector")

        # (re)build our metadata cache of the underlying database
        delta = self._refresh_database_metadata()

        # (re)map each set of loaded coverage data to the database
        self._refresh_database_coverage(delta)

    #----------------------------------------------------------------------
    # Refresh Internals
    #----------------------------------------------------------------------

    def _refresh_database_metadata(self):
        """
        Refresh the database metadata cache utilized by the director.
        """
        logger.debug("Refreshing database metadata")

        # compute the metadata for the current state of the database
        new_metadata = DatabaseMetadata()

        # compute the delta between the old metadata, and latest
        delta = MetadataDelta(new_metadata, self.metadata)

        # save the new metadata in place of the old metadata
        self._database_metadata = new_metadata

        # finally, return the list of nodes that have changed (the delta)
        return delta

    def _refresh_database_coverage(self, delta):
        """
        Refresh the database coverage mappings managed by the director.
        """
        logger.debug("Refreshing database coverage mappings")

        for name, coverage in self._database_coverage.iteritems():
            logger.debug(" - %s" % name)
            coverage.refresh(self.metadata, delta)

    #----------------------------------------------------------------------
    # Painting / TODO: move/remove?
    #----------------------------------------------------------------------

    def paint_coverage(self):
        """
        Paint the active coverage to the database.

        NOTE/TODO:

          I am not convinced the director should have any of the
          painting code. this may be refactored out.

        """
        logger.debug("Painting active coverage")

        # refresh the palette to ensure our colors appropriate for painting.
        self._palette.refresh_colors()

        # color the database based on coverage
        paint_coverage(self.metadata, self.coverage, self._palette.ida_coverage)

    def unpaint_coverage(self):
        """
        Unpaint the active coverage from the database.

        NOTE/TODO:

          Please note that this 'unpainting' implementation is only a
          temporary implementation for Lighthouse v0.2.0. The next version
          will only bother to un-paint the delta between the 'old' and
          the 'new' coverage sets.

        """
        if self.coverage:
            unpaint_coverage(self.metadata, self.coverage)
