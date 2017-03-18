import time
import logging
import collections

from lighthouse.util import *
from lighthouse.painting import *
from lighthouse.metadata import DatabaseMetadata, MetadataDelta
from lighthouse.coverage import DatabaseCoverage
from lighthouse.composer.parser import TokenLogicOperator, TokenCoverageRange, TokenCoverageSingle, TokenNull

logger = logging.getLogger("Lighthouse.Director")

#------------------------------------------------------------------------------
# Constant Definitions
#------------------------------------------------------------------------------

HOT_SHELL = "Hot Shell"
AGGREGATE = "Aggregate"

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
        self._NULL_COVERAGE = DatabaseCoverage(idaapi.BADADDR, None, palette)

        # database metadata cache
        self._database_metadata = None

        # loaded or composed database coverage mappings
        self._database_coverage = {}

        #
        # NOTE:
        #   The ordering of the dict below is the order that its items will
        #   be shown in lists such as UI dropwdowns, etc.
        #

        # special / director generated coverage mappings
        self._special_coverage = collections.OrderedDict(
        [
            (HOT_SHELL, self._NULL_COVERAGE),
            (AGGREGATE, self._NULL_COVERAGE),
        ])

        # shorthand symbol --> coverage_name mappings
        self._shorthand = \
        {
            '*': AGGREGATE
        }

        # the active coverage name
        self.coverage_name  = None
        self.shorthand_name = None

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
        return self.get_coverage(self.coverage_name)

    @property
    def coverage_names(self):
        """
        The names of loaded / composed coverage data.
        """
        return self._database_coverage.keys()

    @property
    def special_names(self):
        """
        The names of special / director coverage.
        """
        return self._special_coverage.keys()

    @property
    def all_names(self):
        """
        The names of both special & loaded/composed coverage data.
        """
        return self.coverage_names + self.special_names

    #----------------------------------------------------------------------
    # Coverage
    #----------------------------------------------------------------------

    def select_coverage(self, coverage_name):
        """
        Activate loaded coverage by name.
        """
        logger.debug("Selecting coverage %s" % coverage_name)

        #
        # before switching to the new coverage, we want to un-paint
        # whatever will NOT be painted over by the new coverage data.
        #

        self.unpaint_difference(self.coverage, self.get_coverage(coverage_name))

        # switch out the director's active coverage set
        self.coverage_name = coverage_name
        #self.shorthand_name = self._shorthand[coverage_name]

        #
        # now we paint using the active coverage. any paint that was left over
        # from the last coverage set will get painted over here (and more)
        #

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
        new_coverage.update_metadata(self.metadata)
        new_coverage.refresh()

        #
        # coverage creation & mapping complete, looks like we're good. add the
        # new coverage to the director's coverage table and surface it for use.
        #

        self._shorthand[chr(ord('A') + len(self._shorthand) - 1)] = coverage_name
        self._database_coverage[coverage_name] = new_coverage

        #
        # TODO/PERF:
        #
        #   If we are calling add_coverage 1000x times, we don't want to
        #   refresh the aggregate set every time... we will want to
        #   restructure things such that we can refresh once only after a
        #   batch load
        #

        # add the newly loaded coverage to the aggregate set
        self._special_coverage[AGGREGATE] |= self._database_coverage[coverage_name]
        self._special_coverage[AGGREGATE].update_metadata(self.metadata)
        self._special_coverage[AGGREGATE].refresh()

    def get_coverage(self, coverage_name):
        """
        Retrieve coverage data for the requested coverage_name.
        """

        # no active coverage, return a blank coverage set
        if not coverage_name:
            return self._NULL_COVERAGE

        # attempt to retrieve the coverage from loaded / computed coverages
        if coverage_name in self._database_coverage:
            return self._database_coverage[coverage_name]

        # attempt to retrieve the coverage from the special directory coverages
        if coverage_name in self._special_coverage:
            return self._special_coverage[coverage_name]

        raise ValueError("No coverage data found for %s" % coverage_name)

    #----------------------------------------------------------------------
    # Composing
    #----------------------------------------------------------------------

    def apply_composition(self, ast):
        """
        Compute the given composition, and store it as applicable.
        """

        composite_coverage = self._evaluate_composition(ast)

        if self.coverage_name == HOT_SHELL:

            composite_coverage.update_metadata(self.metadata)
            composite_coverage.refresh()

            self.unpaint_difference(self.coverage, composite_coverage)
            self._database_coverage[self.coverage_name] = composite_coverage
            self.paint_coverage()
            self.refresh()

            return True

        return False

    def _evaluate_composition(self, ast):
        """
        Evaluate the coverage composition described by the AST.
        """

        # if the AST is effectively 'null', return a blank coverage set
        if isinstance(ast, TokenNull):
            return self._NULL_COVERAGE

        # recursively evaluate the AST
        return self._evaluate_composition_recursive(ast)

    def _evaluate_composition_recursive(self, node):
        """
        The internal (recursive) AST evaluation routine.
        """

        #
        # if the current node is a logic operator, we need to evaluate the
        # expressions that make up its input. only once each operand has
        # been reduced is it appropriate for us to manipulate them
        #

        if isinstance(node, TokenLogicOperator):
            op1 = self._evaluate_composition_recursive(node.op1)
            op2 = self._evaluate_composition_recursive(node.op2)
            return node.operator(op1, op2)

        #
        # if the current node is a coverage range, we need to evaluate the
        # range expression. this will produce an aggregate coverage set
        # described by the start/end of the range (Eg, 'A,D')
        #

        elif isinstance(node, TokenCoverageRange):
            return self._evaluate_coverage_range(node)

        #
        # if the current node is a coverage token, we need simply need
        # to return its associated DatabaseCoverage.
        #

        elif isinstance(node, TokenCoverageSingle):
            return self._evaluate_coverage(node)

        #
        # unknown token? (this should never happen)
        #

        raise ValueError("Invalid AST Token in Composition Tree")

    def _evaluate_coverage(self, coverage_token):
        """
        Evaluate a TokenCoverageSingle AST token.

        Returns an existing coverage set.
        """
        assert isinstance(coverage_token, TokenCoverageSingle)
        return self.get_coverage(self._shorthand[coverage_token.symbol])

    def _evaluate_coverage_range(self, range_token):
        """
        Evaluate a TokenCoverageRange AST token.

        Returns a new aggregate coverage set.
        """
        assert isinstance(range_token, TokenCoverageRange)

        # initialize output to a null coverage set
        output = self._NULL_COVERAGE

        # exapand 'A,Z' to ['A', 'B', 'C', ... , 'Z']
        symbols = [chr(x) for x in range(ord(range_token.symbol_start), ord(range_token.symbol_end) + 1)]
        print "evaluating range", symbols

        # build a coverage aggregate described by the range of shorthand symbols
        for symbol in symbols:
            output = output | self.get_coverage(self._shorthand[symbol])

        # return the computed coverage
        return output

    #----------------------------------------------------------------------
    # Refresh
    #----------------------------------------------------------------------

    def refresh(self):
        """
        Complete refresh of coverage mapping to the active database.
        """
        logger.debug("Refreshing the CoverageDirector")

        # (re)build our metadata cache of the underlying database
        delta = self._refresh_database_metadata()

        # (re)map each set of loaded coverage data to the database
        self._refresh_database_coverage(delta)

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

        for name in self.all_names:
            logger.debug(" - %s" % name)
            coverage = self.get_coverage(name)
            coverage.update_metadata(self.metadata, delta)
            coverage.refresh()

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
        paint_coverage(self.coverage, self._palette.ida_coverage)

    def unpaint_difference(self, old_coverage, new_coverage):
        """
        Clear paint on the difference of two coverage sets.
        """
        logger.debug("Clearing paint difference between coverages")

        # compute the difference in coverage between two sets of coverage
        difference = old_coverage - new_coverage
        difference.update_metadata(self.metadata)
        difference.refresh_nodes()

        # clear the paint on the computed difference
        unpaint_coverage(difference)
