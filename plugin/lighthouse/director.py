import time
import string
import logging
import weakref
import collections

from lighthouse.util import *
from lighthouse.painting import *
from lighthouse.metadata import DatabaseMetadata, MetadataDelta
from lighthouse.coverage import DatabaseCoverage
from lighthouse.composer.parser import TokenLogicOperator, TokenCoverageRange, TokenCoverageSingle, TokenNull

logger = logging.getLogger("Lighthouse.Director")

#------------------------------------------------------------------------------
# Constants Definitions
#------------------------------------------------------------------------------

HOT_SHELL       = "Hot Shell"
NEW_COMPOSITION = "New Composition"
AGGREGATE       = "Aggregate"
SPECIAL_NAMES   = set([HOT_SHELL, AGGREGATE, NEW_COMPOSITION])

AGGREGATE_ALIAS = '*'
ASCII_SHORTHAND = list(string.ascii_uppercase)
SHORTHAND_ALIASES = set([AGGREGATE_ALIAS]) | set(ASCII_SHORTHAND)

RESERVED_NAMES = SHORTHAND_ALIASES | SPECIAL_NAMES

#------------------------------------------------------------------------------
# The Coverage Director
#------------------------------------------------------------------------------

class CoverageDirector(object):
    """
    The Coverage Director manages loaded coverage.

    The primary role of the director is to centralize the loaded coverage
    and provide a platform for researchers to explore the relationship
    between multiple coverage sets.
    """

    def __init__(self, palette):
        self._NULL_COVERAGE = DatabaseCoverage(idaapi.BADADDR, None, palette)

        # color palette
        self._palette = palette

        # database metadata cache
        self._database_metadata = DatabaseMetadata(False)

        #----------------------------------------------------------------------
        # Coverage
        #----------------------------------------------------------------------

        # active coverage name (eg filename)
        self.coverage_name = NEW_COMPOSITION

        # loaded or composed database coverage mappings
        self._database_coverage = collections.OrderedDict()

        #
        # the director automatically maintains or generates a few coverage
        # sets of its own. these are not directly modifiable by the user,
        # but may be influenced by user actions, or loaded coverage data.
        #
        # NOTE:
        #   The ordering of the dict below is the order that its items will
        #   be shown in lists such as UI dropwdowns, etc.
        #

        self._special_coverage = collections.OrderedDict(
        [
            (HOT_SHELL, self._NULL_COVERAGE),       # hot shell composition
            (NEW_COMPOSITION, self._NULL_COVERAGE), # slow shell composition
            (AGGREGATE, self._NULL_COVERAGE),       # aggregate composition
        ])

        #----------------------------------------------------------------------
        # Aliases
        #----------------------------------------------------------------------
        #
        #   Within the director, one is allowed to alias the names of the
        #   loaded coverage data it maintains. right now this is only used
        #   to assign shorthand names to coverage data.
        #
        #   in the future, this can be used for more fun/interesting user
        #   mappings and aliases :-)
        #

        #
        # mapping of alias --> coverage_name
        #   eg: 'A' --> 'my_loaded_coverage.log'
        #

        self._alias2name = {}

        #
        # mapping of coverage_name --> set(aliases)
        #   eg: 'my_loaded_coverage.log' --> set('A', 'log1', 'foo')
        #

        self._name2alias = collections.defaultdict(set)

        #
        # shorthand 'symbols' are aliases that the director automatically
        # assigns to database coverage objects. these special aliases
        # consist of a single capital letter, eg 'A'
        #
        # these auto-aliased shorthand symbols were intended to be a less
        # cumbersome way to reference specific coverage sets while composing.
        #
        # Example -
        #
        #  given these shorthand aliases:
        #
        #   'A' --> 'drcov.boombox.exe.04936.0000.proc.log'
        #   'B' --> 'drcov.boombox.exe.03297.0000.proc.log'
        #   'C' --> 'drcov.boombox.exe.08438.0000.proc.log'
        #   'D' --> 'drcov.boombox.exe.02349.0000.proc.log'
        #   ...
        #   'Z' --> 'drcov.boombox.exe.50946.0000.proc.log'
        #   <eof>
        #
        #  one can more naturally compose interesting equations
        #
        #   ((A & B) | (D & (E - F))) | Z
        #
        # the existing limitation of shorthand symbols is that there is
        # only 26 (A-Z) aliases that can be assigned to coverage sets. There
        # is no immediate plans to further expand this range.
        #
        # the primary justification for this limitation is that I don't
        # expect users to be building complex compositions with 26+ coverage
        # sets loaded at once. At that point, shorthand aliases really
        # aren't going to make things any less cumbersome.
        #

        self._shorthand = collections.deque(ASCII_SHORTHAND)

        #
        # assign default aliases
        #

        # alias the aggregate set to '*'
        self._alias_coverage(AGGREGATE, AGGREGATE_ALIAS)

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------
        #
        #   As the director is the data source for much of Lighthouse, it
        #   is important that anything built ontop of it can act on key
        #   events or changes to the underlying data they consume.
        #
        #   Callbacks provide a way for us to notify any interested
        #   parties of these key events.
        #

        # lists of registered notification callbacks, see 'Signals' below
        self._coverage_switched_callbacks = []
        self._coverage_modified_callbacks = []
        self._coverage_created_callbacks  = []
        self._coverage_deleted_callbacks  = []

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

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
    # Signals
    #----------------------------------------------------------------------

    def coverage_switched(self, callback):
        """
        Subscribe a callback for coverage switch events.
        """
        self._register_callback(self._coverage_switched_callbacks, callback)

    def _notify_coverage_switched(self):
        """
        Notify listeners of a coverage switch event.
        """
        self._notify_callback(self._coverage_switched_callbacks)

    def coverage_modified(self, callback):
        """
        Subscribe a callback for coverage modification events.
        """
        self._register_callback(self._coverage_modified_callbacks, callback)

    def _notify_coverage_modified(self):
        """
        Notify listeners of a coverage modification event.
        """
        self._notify_callback(self._coverage_modified_callbacks)

    def coverage_created(self, callback):
        """
        Subscribe a callback for coverage creation events.
        """
        self._register_callback(self._coverage_created_callbacks, callback)

    def _notify_coverage_created(self):
        """
        Notify listeners of a coverage creation event.
        """
        self._notify_callback(self._coverage_created_callbacks) # TODO: send list of names created?

    def coverage_deleted(self, callback):
        """
        Subscribe a callback for coverage deletion events.
        """
        self._register_callback(self._coverage_deleted_callbacks, callback)

    def _notify_coverage_deleted(self):
        """
        Notify listeners of a coverage deletion event.
        """
        self._notify_callback(self._coverage_deleted_callbacks) # TODO: send list of names deleted?

    def _register_callback(self, callback_list, callback):
        """
        Internal callback registration.

        Adapted from http://stackoverflow.com/a/21941670
        """

        # create a weakref callback to an object method
        try:
            callback_ref = weakref.ref(callback.__func__), weakref.ref(callback.__self__)

        # create a wweakref callback to a stand alone function
        except AttributeError:
            callback_ref = weakref.ref(callback), None

        # register the callback
        callback_list.append(callback_ref)

    def _notify_callback(self, callback_list):
        """
        Internal callback notification.

        The given list is expected to consist of all items registered to the
        same type of callback.

         eg:
           self._coverage_switched_callbacks
           self._coverage_modified_callbacks
           self._coverage_created_callbacks
           self._coverage_deleted_callbacks

        Adapted from http://stackoverflow.com/a/21941670
        """
        cleanup = []

        #
        # loop through all the registered callbacks in the given callback_list,
        # notifying active callbacks, and removing dead ones.
        #

        for callback_ref in callback_list:
            callback, obj_ref = callback_ref[0](), callback_ref[1]

            # if the callback is an instance method...
            if obj_ref:
                obj = obj_ref()

                # if the object instance is gone, mark this callback for cleanup
                if obj is None:
                    cleanup.append(callback_ref)
                    continue

                # call the object instance callback
                callback(obj)

            # if the callback is a static method...
            else:

                # if the static method is deleted, mark this callback for cleanup
                if callback is None:
                    cleanup.append(callback_ref)
                    continue

                # call the static callback
                callback(self)

        # remove the deleted callbacks
        for callback_ref in cleanup:
            callback_list.remove(callback_ref)

    #----------------------------------------------------------------------
    # Coverage
    #----------------------------------------------------------------------

    def select_coverage(self, coverage_name):
        """
        Activate loaded coverage by name.
        """
        logger.debug("Selecting coverage %s" % coverage_name)

        # ensure coverage data actually exists for the given coverage_name
        if not (coverage_name in self.all_names):
            raise ValueError("No coverage matching '%s' was found" % coverage_name)

        #
        # if the requested switch target matches the currently active
        # coverage, then there's nothing for us to do
        #

        if self.coverage_name == coverage_name:
            return

        #
        # before switching to the new coverage, we want to un-paint
        # whatever will NOT be painted over by the new coverage data.
        #

        self.unpaint_difference(self.coverage, self.get_coverage(coverage_name))

        #
        # switch out the active coverage name with the new coverage name.
        # this pivots the director
        #

        self.coverage_name = coverage_name

        #
        # now we paint using the active coverage. any paint that was left over
        # from the last coverage set will get painted over here (and more)
        #

        self.paint_coverage()

        # notify any listeners that we have switched our active coverage
        self._notify_coverage_switched()

    def add_coverage(self, coverage_name, coverage_base, coverage_data):
        """
        Add new coverage to the director.

        This is effectively an alias of self.update_coverage
        """
        self.update_coverage(coverage_name, coverage_base, coverage_data)

    def update_coverage(self, coverage_name, coverage_base, coverage_data):
        """
        Add or update coverage maintained by the director.
        """
        assert not (coverage_name in RESERVED_NAMES)
        updating_coverage = coverage_name in self.coverage_names

        if updating_coverage:
            logger.debug("Updating coverage %s" % coverage_name)
        else:
            logger.debug("Adding coverage %s" % coverage_name)

        # create & map a new database coverage object using the given data
        new_coverage = self._build_coverage(coverage_base, coverage_data)

        # coverage mapping complete, looks like we're good. add the new
        # coverage to the director's coverage table and surface it for use.
        self._update_coverage(coverage_name, new_coverage)

        # assign a shorthand alias (if available) to new coverage additions
        if not updating_coverage:
            self._request_shorthand_alias(coverage_name)

        # notify any listeners that we have added or updated coverage
        if updating_coverage:
            self._notify_coverage_modified()
        else:
            self._notify_coverage_created()

    def _update_coverage(self, coverage_name, new_coverage):
        """
        Internal add/update of coverage.

        This will automatically update the director's aggregate.
        """

        #
        # if there exists coverage data under the coverage_name we are trying
        # to add/update, we first must remove anything it has contributed to
        # the aggregate before we dispose of its data
        #

        if coverage_name in self.coverage_names:

            # TODO: hack to be removed in v0.4.0
            aggregate = self._special_coverage[AGGREGATE]
            coverage  = self._database_coverage[coverage_name]

            self._special_coverage[AGGREGATE] = aggregate.hitmap_subtract(coverage)
            self._special_coverage[AGGREGATE].update_metadata(self.metadata)
            self._special_coverage[AGGREGATE].refresh()

        #
        # this is the critical point where we actually integrate the newly
        # built coverage into the director, replacing any existing entries
        #

        self._database_coverage[coverage_name] = new_coverage

        #
        # TODO/PERF:
        #
        #   If we are calling add_coverage 1000x times, we don't want to
        #   refresh the aggregate set every time... we will want to
        #   restructure things such that we can refresh once only after a
        #   batch load
        #

        # (re)-add the newly loaded/updated coverage to the aggregate set
        self._special_coverage[AGGREGATE] |= new_coverage
        self._special_coverage[AGGREGATE].update_metadata(self.metadata) # TODO: delta?
        self._special_coverage[AGGREGATE].refresh()

    def _build_coverage(self, coverage_base, coverage_data):
        """
        Build a new database coverage object from the given data.
        """

        # initialize a new database-wide coverage object for this data
        new_coverage = DatabaseCoverage(coverage_base, coverage_data, self._palette)

        # map the coverage data using the database metadata
        new_coverage.update_metadata(self.metadata)
        new_coverage.refresh()

        return new_coverage

    def delete_coverage(self, coverage_name):
        """
        Delete a database coverage object by name.
        """
        assert coverage_name in self.coverage_names

        #
        # if the delete request targets the currently active coverage, we want
        # to switch into a safer coverage to try and avoid any ill effects.
        #

        if self.coverage_name == coverage_name:
            self.select_coverage(NEW_COMPOSITION)

        # release the shorthand alias held by this coverage
        self._release_shorthand_alias(coverage_name)

        # delete the database coverage object
        coverage = self._database_coverage.pop(coverage_name)
        # TODO: check if there's any references to the coverage object here...

        # TODO: hack to be removed in v0.4.0
        aggregate = self._special_coverage[AGGREGATE]
        self._special_coverage[AGGREGATE] = aggregate.hitmap_subtract(coverage)
        self._special_coverage[AGGREGATE].update_metadata(self.metadata) # TODO: delta?
        self._special_coverage[AGGREGATE].refresh()

        # notify any listeners that we have deleted coverage
        self._notify_coverage_deleted()

    def get_coverage(self, name):
        """
        Retrieve coverage data for the requested coverage_name.
        """

        # no matching coverage, return a blank coverage set
        if not name:
            return self._NULL_COVERAGE

        # if the given name was an alias, dereference it now
        coverage_name = self._alias2name.get(name, name)

        # attempt to retrieve the coverage from loaded / computed coverages
        if coverage_name in self.coverage_names:
            return self._database_coverage[coverage_name]

        # attempt to retrieve the coverage from the special directory coverages
        if coverage_name in self.special_names:
            return self._special_coverage[coverage_name]

        raise ValueError("No coverage data found for %s" % coverage_name)

    def get_coverage_string(self, coverage_name):
        """
        Retrieve a detailed coverage string for the given coverage_name.
        """

        # special case
        if coverage_name == HOT_SHELL or coverage_name == NEW_COMPOSITION:
            return coverage_name

        symbol   = self.get_shorthand(coverage_name)
        coverage = self.get_coverage(coverage_name)

        #
        # build a detailed coverage string
        #   eg: 'A - 73.45% - drcov.boombox.exe.03820.0000.proc.log'
        #

        coverage_string = "%s - %5.2f%% - %s" % \
            (symbol, coverage.instruction_percent*100, coverage_name)

        return coverage_string

    #----------------------------------------------------------------------
    # Aliases
    #----------------------------------------------------------------------

    def alias_coverage(self, coverage_name, alias):
        """
        Assign an alias to loaded coverage.
        """
        assert not (alias in self.all_names)
        assert not (alias in RESERVED_NAMES)
        self._alias_coverage(coverage_name, alias)

    def _alias_coverage(self, coverage_name, alias):
        """
        Internal alias assignment routine. No restrictions.
        """

        #
        # if we are overwriting a known alias, we should remove its
        # inverse mapping reference in the name --> [aliases] map first
        #

        if alias in self._alias2name:
            self._name2alias[self._alias2name[alias]].remove(alias)

        # save the new alias
        self._alias2name[alias] = coverage_name
        self._name2alias[coverage_name].add(alias)

    def get_aliases(self, coverage_name):
        """
        Retrieve alias set for the requested coverage_name.
        """
        return self._name2alias[coverage_name]

    def get_shorthand(self, coverage_name):
        """
        Retrieve shorthand symbol for the requested coverage.
        """
        try:

            # reduce the coverage's aliases to only shorthand candidates
            shorthand = self._name2alias[coverage_name] & SHORTHAND_ALIASES

            # there can only ever be up to 1 shorthand symbols for a given coverage
            assert len(shorthand) < 2

            # pop the single shorthand symbol (if one is even aliased)
            return shorthand.pop()

        # there doesn't appear to be a shorthand symbol...
        except KeyError:
            return None

    #----------------------------------------------------------------------
    # Composing
    #----------------------------------------------------------------------

    def accept_composition(self, coverage_name):
        """
        Save the last known composition to the specified name.

        TODO:
          this paradigm of 'last_ast' seems wonky, but it should make more
          sense as things are moved async in v0.4.0

        """
        assert not (coverage_name in RESERVED_NAMES)
        updating_coverage = coverage_name in self.coverage_names
        logger.debug("Accepting composition %s" % coverage_name)

        # evaluate the last AST into a coverage set
        composite_coverage = self._evaluate_composition(self._last_ast)
        composite_coverage.update_metadata(self.metadata)
        composite_coverage.refresh()

        # save the evaluated coverage under the given name
        self._update_coverage(coverage_name, composite_coverage)

        # assign a shorthand alias (if available) to new coverage additions
        if not updating_coverage:
            self._request_shorthand_alias(coverage_name)

        # notify any listeners that we have added or updated coverage
        if updating_coverage:
            self._notify_coverage_modified()
        else:
            self._notify_coverage_created()

    def cache_composition(self, ast):
        """
        Cache the given composition.
        """

        # hot shell requests are evaluated immediately
        if self.coverage_name == HOT_SHELL:

            composite_coverage = self._evaluate_composition(ast)
            composite_coverage.update_metadata(self.metadata)
            composite_coverage.refresh()

            self.unpaint_difference(self.coverage, composite_coverage)
            self._special_coverage[HOT_SHELL] = composite_coverage
            self.paint_coverage()

            self._notify_coverage_modified()

        #
        # TODO:
        #   in v0.4.0 we will actually offload the AST to be evaluated
        #   in an async thread and cache that
        #

        # cache this request as the last known user AST
        self._last_ast = ast

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
        return self.get_coverage(self._alias2name[coverage_token.symbol])

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

        # build a coverage aggregate described by the range of shorthand symbols
        for symbol in symbols:
            output = output | self.get_coverage(self._alias2name[symbol])

        # return the computed coverage
        return output

    #----------------------------------------------------------------------
    # Refresh
    #----------------------------------------------------------------------

    def refresh(self):
        """
        Complete refresh of the director and mapped coverage.
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

    def _request_shorthand_alias(self, coverage_name):
        """
        Assign the next shorthand A-Z alias to the given coverage.
        """
        logger.debug("Requesting shorthand alias for %s" % coverage_name)
        assert coverage_name in self.coverage_names

        # get the next symbol (A-Z) from the shorthand pool
        try:
            symbol = self._shorthand.popleft()
        except IndexError:
            return None

        # alias the shorthand to the given coverage_name
        self._alias_coverage(coverage_name, symbol)

        # return the alias symbol assigned
        return symbol

    def _release_shorthand_alias(self, coverage_name):
        """
        Release the shorthand alias of the given coverage_name.
        """
        logger.debug("Releasing shorthand alias for %s" % coverage_name)
        assert coverage_name in self.coverage_names

        # get the shorthand symbol for the given coverage
        symbol = self.get_shorthand(coverage_name)

        # if there was no symbol assigned, there's nothing to do
        if not symbol:
            return

        # delete the shorthand symbol from the alias maps
        self._name2alias[coverage_name].remove(symbol)
        self._alias2name.pop(symbol)

        # add the symbol back to the end of the shorthand pool
        self._shorthand.append(symbol)

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
        #self._palette.refresh_colors()

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
