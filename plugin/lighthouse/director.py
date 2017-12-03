import time
import string
import logging
import threading
import collections

from lighthouse.util import *
from lighthouse.metadata import DatabaseMetadata, MetadataDelta
from lighthouse.coverage import DatabaseCoverage
from lighthouse.composer.parser import *

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

        # color palette
        self._palette = palette

        # database metadata cache
        self.metadata = DatabaseMetadata()

        # flag to suspend/resume the automatic coverage aggregation
        self._aggregation_suspended = False

        #----------------------------------------------------------------------
        # Coverage
        #----------------------------------------------------------------------

        # the name of the active coverage (eg filename)
        self.coverage_name = NEW_COMPOSITION

        # loaded or composed database coverage mappings
        self._database_coverage = collections.OrderedDict()

        # a NULL / empty coverage set
        self._NULL_COVERAGE = DatabaseCoverage(None, palette)

        #
        # the director automatically maintains or generates a few coverage
        # sets of its own. these are not directly modifiable by the user,
        # but may be influenced by user actions, or loaded coverage data.
        #
        # NOTE: The ordering of the dict below is the order that its items
        # will be shown in lists such as UI dropwdowns, etc.
        #

        self._special_coverage = collections.OrderedDict(
        [
            (HOT_SHELL,       DatabaseCoverage(None, palette)), # hot shell composition
            (NEW_COMPOSITION, DatabaseCoverage(None, palette)), # slow shell composition
            (AGGREGATE,       DatabaseCoverage(None, palette)), # aggregate composition
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
        # Async
        #----------------------------------------------------------------------

        self._ast_queue = Queue.Queue()
        self._composition_lock = threading.Lock()
        self._composition_cache = CompositionCache()

        self._composition_worker = threading.Thread(
            target=self._async_evaluate_ast,
            name="EvaluateAST"
        )
        self._composition_worker.start()

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------
        #
        #   As the director is the data source for much of Lighthouse, it
        #   is important that anything built ontop of it can act on key
        #   events or changes to the underlying data they consume.
        #
        #   Callbacks provide a way for us to notify any interested parties
        #   of these key events. Below are lists of registered notification
        #   callbacks. see 'Callbacks' section below for more info.
        #

        # coverage callbacks
        self._coverage_switched_callbacks = []
        self._coverage_modified_callbacks = []
        self._coverage_created_callbacks  = []
        self._coverage_deleted_callbacks  = []

        # metadata callbacks
        self._metadata_modified_callbacks = []

    def terminate(self):
        """
        Cleanup & terminate the director.
        """

        # stop the composition worker
        self._ast_queue.put(None)
        self._composition_worker.join()

        # stop any ongoing metadata refresh
        self.metadata.abort_refresh(join=True)

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def coverage(self):
        """
        The active database coverage.
        """
        return self.get_coverage(self.coverage_name)

    @property
    def aggregate(self):
        """
        The aggregate of loaded data.
        """
        return self._special_coverage[AGGREGATE]

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
    # Callbacks
    #----------------------------------------------------------------------

    def coverage_switched(self, callback):
        """
        Subscribe a callback for coverage switch events.
        """
        register_callback(self._coverage_switched_callbacks, callback)

    def _notify_coverage_switched(self):
        """
        Notify listeners of a coverage switch event.
        """
        notify_callback(self._coverage_switched_callbacks)

    def coverage_modified(self, callback):
        """
        Subscribe a callback for coverage modification events.
        """
        register_callback(self._coverage_modified_callbacks, callback)

    def _notify_coverage_modified(self):
        """
        Notify listeners of a coverage modification event.
        """
        notify_callback(self._coverage_modified_callbacks)

    def coverage_created(self, callback):
        """
        Subscribe a callback for coverage creation events.
        """
        register_callback(self._coverage_created_callbacks, callback)

    def _notify_coverage_created(self):
        """
        Notify listeners of a coverage creation event.
        """
        notify_callback(self._coverage_created_callbacks) # TODO: send list of names created?

    def coverage_deleted(self, callback):
        """
        Subscribe a callback for coverage deletion events.
        """
        register_callback(self._coverage_deleted_callbacks, callback)

    def _notify_coverage_deleted(self):
        """
        Notify listeners of a coverage deletion event.
        """
        notify_callback(self._coverage_deleted_callbacks) # TODO: send list of names deleted?

    def metadata_modified(self, callback):
        """
        Subscribe a callback for metadata modification events.
        """
        register_callback(self._metadata_modified_callbacks, callback)

    def _notify_metadata_modified(self):
        """
        Notify listeners of a metadata modification event.
        """
        notify_callback(self._metadata_modified_callbacks)

    #----------------------------------------------------------------------
    # Batch Loading
    #----------------------------------------------------------------------

    def suspend_aggregation(self):
        """
        Suspend the aggregate computation for any newly added coverage.

        It is performant to suspend/resume aggregation if loading a number
        of individual coverage files. This will prevent the aggregate
        coverage set from being re-computed multiple times.
        """
        self._aggregation_suspended = True

    def resume_aggregation(self):
        """
        Resume the aggregate computation.
        """
        assert self._aggregation_suspended
        self._refresh_aggregate()
        self._aggregation_suspended = False

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
        # switch out the active coverage name with the new coverage name.
        # this pivots the director
        #

        self.coverage_name = coverage_name

        # notify any listeners that we have switched our active coverage
        self._notify_coverage_switched()

    def create_coverage(self, coverage_name, coverage_data):
        """
        Create a new coverage object maintained by the director.

        This is effectively an alias of self.update_coverage
        """
        return self.update_coverage(coverage_name, coverage_data)

    def update_coverage(self, coverage_name, coverage_data):
        """
        Create or update a coverage object.
        """
        assert not (coverage_name in RESERVED_NAMES)
        updating_coverage = coverage_name in self.coverage_names

        if updating_coverage:
            logger.debug("Updating coverage %s" % coverage_name)
        else:
            logger.debug("Adding coverage %s" % coverage_name)

        # create & map a new database coverage object using the given data
        new_coverage = self._new_coverage(coverage_data)

        #
        # coverage mapping complete, looks like we're good. add the new
        # coverage to the director's coverage table and surface it for use.
        #

        self._update_coverage(coverage_name, new_coverage)

        # assign a shorthand alias (if available) to new coverage additions
        if not updating_coverage:
            self._request_shorthand_alias(coverage_name)

        # notify any listeners that we have added or updated coverage
        if updating_coverage:
            self._notify_coverage_modified()
        else:
            self._notify_coverage_created()

        # return the created/updated coverage
        return new_coverage

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
            old_coverage = self._database_coverage[coverage_name]
            self.aggregate.subtract_data(old_coverage.data)
            if not self._aggregation_suspended:
                self._refresh_aggregate()

        #
        # this is the critical point where we actually integrate the newly
        # built coverage into the director, replacing any existing entries
        #

        self._database_coverage[coverage_name] = new_coverage

        # (re)-add the newly loaded/updated coverage to the aggregate set
        self.aggregate.add_data(new_coverage.data)
        if not self._aggregation_suspended:
            self._refresh_aggregate()

    def _new_coverage(self, coverage_data):
        """
        Build a new database coverage object from the given data.
        """
        new_coverage = DatabaseCoverage(coverage_data, self._palette)
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

        self.aggregate.subtract_data(coverage.data)
        if not self._aggregation_suspended:
            self._refresh_aggregate()

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

    def peek_shorthand(self):
        """
        Peek at the next available shorthand symbol.
        """
        try:
            return self._shorthand[0]
        except IndexError:
            return None

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
    # Composing
    #----------------------------------------------------------------------

    def add_composition(self, composite_name, ast):
        """
        Evaluate and add a new composition to the director.
        """
        assert not (composite_name in RESERVED_NAMES)
        updating_coverage = composite_name in self.coverage_names
        logger.debug("Adding composition %s" % composite_name)

        # evaluate the last AST into a coverage set
        composite_coverage = self._evaluate_composition(ast)

        # save the evaluated coverage under the given name
        self._update_coverage(composite_name, composite_coverage)

        # assign a shorthand alias (if available) to new coverage additions
        if not updating_coverage:
            self._request_shorthand_alias(composite_name)

        # notify any listeners that we have added or updated coverage
        if updating_coverage:
            self._notify_coverage_modified()
        else:
            self._notify_coverage_created()

    def cache_composition(self, ast, force=False):
        """
        Cache the given composition.
        """
        assert ast

        #
        # normally, we only pro-actively evaluate/cache if the hotshell is
        # active, but we can also allow the caller to force a cache to occur
        #

        if self.coverage_name == HOT_SHELL or force:
            self._ast_queue.put(ast)

    def _async_evaluate_ast(self):
        """
        Asynchronous composition evaluation worker loop.
        """
        logger.debug("Starting EvaluateAST thread...")

        while True:

            # get the next AST to evaluate
            ast = self._ast_queue.get()

            # signal to stop
            if ast == None:
                break

            # produce a single composite coverage object as described by the AST
            composite_coverage = self._evaluate_composition(ast)

            # we always save the most recent composite to the hotshell entry
            self._special_coverage[HOT_SHELL] = composite_coverage

            #
            # if the hotshell entry is the active coverage selection, notify
            # listeners of its update
            #

            if self.coverage_name == HOT_SHELL:
                self._notify_coverage_modified()

            # loop and wait for the next AST to evaluate

        # thread exit
        logger.debug("Exiting EvaluateAST thread...")

    def _evaluate_composition(self, ast):
        """
        Evaluate the coverage composition described by the AST.
        """

        # if the AST is effectively 'null', return a blank coverage set
        if isinstance(ast, TokenNull):
            return self._NULL_COVERAGE

        #
        # the director's composition evaluation code (this function) is most
        # generally called via the background caching evaluation thread known
        # as self._composition_worker. But this function can also be called
        # inline via the 'add_composition' function from a different thread
        # (namely, the main thread)
        #
        # because of this, we must control access to the resources the AST
        # evaluation code operates by restricting the code to one thread
        # at a time.
        #
        # should we call _evaluate_composition from the context of the main
        # IDA thread, it is important that we do so in a pseudo non-blocking
        # such that we don't hang IDA. await_lock(...) will allow the Qt/IDA
        # main thread to yield to other threads while waiting for the lock
        #

        await_lock(self._composition_lock)

        # recursively evaluate the AST
        composite_coverage = self._evaluate_composition_recursive(ast)

        # map the composited coverage data to the database metadata
        composite_coverage.update_metadata(self.metadata)
        composite_coverage.refresh() # TODO: hash refresh?

        # done operating on shared data (coverage), release the lock
        self._composition_lock.release()

        # return the evaluated composition
        return composite_coverage

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

            #
            # collect the left and right components of the logical operation
            #   eg:
            #       op1 = DatabaseCoverage for 'A'
            #       op2 = DatabaseCoverage for 'B'
            #

            op1 = self._evaluate_composition_recursive(node.op1)
            op2 = self._evaluate_composition_recursive(node.op2)

            #
            # Before computing a new composition, we actually compute a hash
            # actually compute a 'hash' of the operation that would normally
            # generate the composition.
            #
            # This 'hash' can be used to index into an LRU based cache that
            # holds compositions created by the AST evaluation process.
            #
            # The 'hash' is actually computed as a product of the operator
            # that would normally combine the two coverage sets.
            #
            # For example, when computing compositions the logical operators
            # (eg |, &, ^), it does not matter which side of the equation the
            # coverage components fall on.
            #  eg:
            #      (A | B) == (B | A)
            #
            # while arithmetic operations (-) will produce different results
            #
            #      (A - B) != (B - A)
            #
            # So if we are being asked to compute a composition of (A | B),
            # we first compute:
            #
            #      composition_hash = hash(A) | hash(B)
            #
            # And use composition_hash to check an LRU cache for the complete
            # evaluation/composition of (A | B).
            #
            # The possibility of collisions are generally higher with this
            # form of 'hash', but I still expect them to be extremely rare.
            #

            composition_hash = node.operator(op1.coverage_hash, op2.coverage_hash)

            #
            # Evaluating an AST produces lots of 'transient' compositions. To
            # mitigate unecessary re-computation, we maintain a small LRU cache
            # of these compositions to draw from during evaluation.
            #
            #   eg:
            #       evaluating the input
            #
            #         (A | B) - (C | D)
            #
            #       produces
            #
            #         COMP_1 = (A | B)
            #         COMP_2 = (C | D)
            #         COMP_3 = COMP_1 - COMP_2
            #
            # In the example above, COMP_3 is the final evaluated result, and
            # COMP_1/COMP_2 would normally be discarded. Instead, we cache all
            # of these compositions (1, 2, 3) as they may be useful to us in
            # the subsequent evaluations.
            #
            # If the user then choses to evaluate (A | B) - (Z | D), our cache
            # can retrieve the fully computed (A | B) composition assuming it
            # has not been evicted.
            #

            # check the cache to see if this composition was recently computed
            cached_coverage = self._composition_cache[composition_hash]

            # if the composition was found in the cache, return that for speed
            if cached_coverage:
                return cached_coverage

            #
            # using the collected components of the logical operation, we
            # compute the coverage mask defined by this TokenLogicOperator
            #

            coverage_mask = node.operator(op1.coverage, op2.coverage)

            #
            # now that we have computed the requested coverage mask (bitmap),
            # apply the mask to the data held by the left operand (op1). we
            # return a masked copy of said DatabaseCoverage
            #

            new_composition = DatabaseCoverage(coverage_mask, self._palette)

            # cache & return the newly computed composition
            self._composition_cache[composition_hash] = new_composition
            return new_composition

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
        output = DatabaseCoverage(None, self._palette)

        # exapand 'A,Z' to ['A', 'B', 'C', ... , 'Z']
        symbols = [chr(x) for x in range(ord(range_token.symbol_start), ord(range_token.symbol_end) + 1)]

        # build a coverage aggregate described by the range of shorthand symbols
        for symbol in symbols:
            output.add_data(self.get_coverage(self._alias2name[symbol]).data)

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

    def refresh_metadata(self, progress_callback=None, force=False):
        """
        Refresh the database metadata cache utilized by the director.

        Returns a future (Queue) that will carry the completion message.
        """

        #
        # if this is the first time the director is going to use / populate
        # the database metadata, register the director for notifications of
        # metadata modification (this should only happen once)
        #
        # TODO: this is a little dirty, but it will suffice.
        #

        if not self.metadata.cached:
            self.metadata.function_renamed(self._notify_metadata_modified)

        #
        # if the lighthouse has collected metadata previously for this IDB
        # session (eg, it is cached), ignore a request to refresh it unless
        # explicitly told to refresh via force=True
        #

        if self.metadata.cached and not force:
            fake_queue = Queue.Queue()
            fake_queue.put(False)
            return fake_queue

        # start the asynchronous metadata refresh
        result_queue = self.metadata.refresh(progress_callback=progress_callback)

        # return the channel that will carry asynchronous result
        return result_queue

    def _refresh_database_metadata(self):
        """
        Refresh the database metadata cache utilized by the director.

        NOTE: this is currently unused.
        """
        logger.debug("Refreshing database metadata")

        # compute the metadata for the current state of the database
        new_metadata = DatabaseMetadata()
        new_metadata.build_metadata()

        # compute the delta between the old metadata, and latest
        delta = MetadataDelta(new_metadata, self.metadata)

        # save the new metadata in place of the old metadata
        self.metadata = new_metadata

        # finally, return the list of nodes that have changed (the delta)
        return delta

    def _refresh_database_coverage(self, delta):
        """
        Refresh all the database coverage mappings managed by the director.
        """
        logger.debug("Refreshing database coverage mappings")

        for name in self.all_names:
            logger.debug(" - %s" % name)
            coverage = self.get_coverage(name)
            coverage.update_metadata(self.metadata, delta)
            coverage.refresh()

    def _refresh_aggregate(self):
        """
        Refresh the aggregate coverage set.
        """
        self.aggregate.update_metadata(self.metadata)
        self.aggregate.refresh()

#------------------------------------------------------------------------------
# Composition Cache
#------------------------------------------------------------------------------

DEFAULT_CACHE_CAPACITY = 30

class CompositionCache(object):
    """
    A simple LRU cache to hold coverage compositions.
    """

    def __init__(self, capacity=DEFAULT_CACHE_CAPACITY):
        self._cache = collections.OrderedDict()
        self._capacity = capacity

    def __getitem__(self, key):
        """
        Get an entry from the cache.
        """
        result = self._cache.pop(key, None)

        # cache hit, raise priority of this item
        if result:
            self._cache[key] = result

        # return the cache entry (or None)
        return result

    def __setitem__(self, key, value):
        """
        Update the cache with the given entry.
        """
        result = self._cache.pop(key, None)

        # item is already in the cache, touch it.
        if result:
            self._cache[key] = result
            return

        # if the cache is full, evict the entry oldest entry
        if len(self._cache) > self._capacity:
            self._cache.popitem(False)

        # insert the new cache entry
        self._cache[key] = value
