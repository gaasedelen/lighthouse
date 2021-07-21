import os
import time
import string
import logging
import threading
import traceback
import collections

from lighthouse.util.misc import *
from lighthouse.util.debug import *
from lighthouse.util.python import *
from lighthouse.util.qt import await_future, await_lock, flush_qt_events
from lighthouse.util.disassembler import disassembler

from lighthouse.ui import ModuleSelector
from lighthouse.reader import CoverageReader
from lighthouse.metadata import DatabaseMetadata, metadata_progress
from lighthouse.coverage import DatabaseCoverage
from lighthouse.exceptions import *
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
    The CoverageDirector manages loaded coverage, and coverage composition.

    This class is the 'brain' of Lighthouse. Its primary role is to centralize
    loaded coverage and switch between which set is 'active'. It also houses
    the logic to perform set operations between loaded coverage.

    This provides a platform for researchers to explore the relationship
    between any number of coverage files.
    """

    def __init__(self, metadata, palette):

        # the database metadata cache
        self.metadata = metadata

        # the plugin color palette
        self.palette = palette

        #----------------------------------------------------------------------
        # Coverage
        #----------------------------------------------------------------------

        # the coverage file parser
        self.reader = CoverageReader()
        self._target_whitelist = []
        self.suppressed_errors = set()

        # the name of the active coverage
        self.coverage_name = NEW_COMPOSITION

        # a map of loaded or composed database coverages
        self._database_coverage = collections.OrderedDict()

        #
        # the owners map is used in block/coverage blame operations. it
        # contains the mapping of node_address --> [ coverage filepaths ]
        #
        # given any node (basic block) address, we can use this mapping to do
        # a reverse lookup to find which loaded coverage sets hit the block.
        #

        self.owners = collections.defaultdict(set)

        #
        # the director automatically maintains / generates a few coverage sets
        # of its own. these are not directly modifiable by the user, but may
        # be influenced by user actions (say, loading new coverage data)
        #
        # Note that the ordering of the dict below is the order that its items
        # will be shown in lists such as the CoverageComboBox dropwdown, etc.
        #

        self._special_coverage = collections.OrderedDict(
        [
            (HOT_SHELL,       DatabaseCoverage(palette, HOT_SHELL)),
            (NEW_COMPOSITION, DatabaseCoverage(palette, NEW_COMPOSITION)),
            (AGGREGATE,       DatabaseCoverage(palette, AGGREGATE)),
        ])

        # a flag to suspend/resume the automatic coverage aggregation
        self._aggregation_suspended = False

        #----------------------------------------------------------------------
        # Aliases
        #----------------------------------------------------------------------

        #
        # Within the director, one is allowed to alias the names of the loaded
        # coverage data that it maintains. right now this is only used to
        # assign shorthand names to coverage data.
        #
        # mapping of {alias: coverage_name}
        #   eg: 'A' --> 'my_loaded_coverage.log'
        #

        self._alias2name = {}

        #
        # mapping of {coverage_name: set(aliases)}
        #   eg: 'my_loaded_coverage.log' --> set(['A', 'log1', 'foo'])
        #

        self._name2alias = collections.defaultdict(set)

        #
        # shorthand 'symbols' are aliases that the director automatically
        # assigns to loaded database coverage mappings. these special aliases
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
        #  one can more naturally compose interesting coverage equations
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
        # Async Composition Computation
        #----------------------------------------------------------------------

        #
        # the director is responsible for computing the logical/arithmetic
        # results of coverage set operations (composing). thanks to our lifted
        # metadata, we can do these set computations completely asynchronously.
        #
        # we use locks, queues, and a background 'composition worker' thread
        # to handle these computation requests.
        #

        self._ast_queue = queue.Queue()
        self._composition_lock = threading.Lock()
        self._composition_cache = CompositionCache()

        self._composition_worker = threading.Thread(
            target=self._async_evaluate_ast,
            name="EvaluateAST"
        )

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------

        #
        # as the director is the data source for much of Lighthouse, it is
        # important that anything built on top of it can act on key events or
        # changes to the underlying data they consume.
        #
        # callbacks provide a way for us to notify any interested parties of
        # these key events. Below are lists of registered notification
        # callbacks. see 'Callbacks' section below for more info.
        #

        # coverage callbacks
        self._coverage_switched_callbacks = []
        self._coverage_modified_callbacks = []
        self._coverage_created_callbacks  = []
        self._coverage_deleted_callbacks  = []

        # director callbacks
        self._refreshed_callbacks  = []

    #--------------------------------------------------------------------------
    # Subsystem Lifetime
    #--------------------------------------------------------------------------

    def start(self):
        """
        Start the metadata subsystem.
        """
        self._composition_worker.start()

    def terminate(self):
        """
        Cleanup & terminate the director.
        """
        self._ast_queue.put(None)
        try:
            self._composition_worker.join()
        except RuntimeError:
            pass

        # best effort to free up resources & improve interpreter spindown
        del self._special_coverage
        del self._database_coverage
        del self._coverage_switched_callbacks
        del self._coverage_modified_callbacks
        del self._coverage_created_callbacks
        del self._coverage_deleted_callbacks
        del self._composition_cache

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def coverage(self):
        """
        Return the active database coverage.
        """
        return self.get_coverage(self.coverage_name)

    @property
    def aggregate(self):
        """
        Return the database coverage aggregate.
        """
        return self._special_coverage[AGGREGATE]

    @property
    def coverage_names(self):
        """
        Return the list or loaded / composed database coverage names.
        """
        return list(self._database_coverage)

    @property
    def special_names(self):
        """
        Return the list of special (director maintained) coverage names.
        """
        return list(self._special_coverage)

    @property
    def all_names(self):
        """
        Return the names of both special & loaded/composed coverage data.
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
        notify_callback(self._coverage_created_callbacks)

    def coverage_deleted(self, callback):
        """
        Subscribe a callback for coverage deletion events.
        """
        register_callback(self._coverage_deleted_callbacks, callback)

    def _notify_coverage_deleted(self):
        """
        Notify listeners of a coverage deletion event.
        """
        notify_callback(self._coverage_deleted_callbacks)

    def refreshed(self, callback):
        """
        Subscribe a callback for director refresh events.
        """
        register_callback(self._refreshed_callbacks, callback)

    def _notify_refreshed(self):
        """
        Notify listeners of a director refresh event.
        """
        notify_callback(self._refreshed_callbacks)

    #----------------------------------------------------------------------
    # Batch Loading
    #----------------------------------------------------------------------

    def resume_aggregation(self):
        """
        Resume automatic updating of the coverage aggregate.
        """
        assert self._aggregation_suspended
        self._refresh_aggregate()
        self._aggregation_suspended = False

    def suspend_aggregation(self):
        """
        Suspend the coverage aggregate from being automatically updated.

        It is performant to suspend/resume aggregation if loading a number
        of individual coverage files. This will prevent the aggregate
        coverage set from being re-computed multiple times.
        """
        self._aggregation_suspended = True

    #----------------------------------------------------------------------
    # Coverage Loading
    #----------------------------------------------------------------------

    def load_coverage_batch(self, filepaths, batch_name, progress_callback=logger.debug):
        """
        Create a new database coverage mapping from a list of coverage files.

        Returns a tuple of (coverage, errors)
        """
        errors = collections.defaultdict(list)
        aggregate_addresses = set()

        # unsupress NO_COVERAGE_ERROR per-load, instead of per-session
        self.suppressed_errors.discard(CoverageMissingError)

        start = time.time()
        #----------------------------------------------------------------------

        for i, filepath in enumerate(filepaths, 1):
            logger.debug("-"*50)
            progress_callback("Aggregating batch data %u/%u" % (i, len(filepaths)))

            # attempt to load coverage data from disk
            try:
                coverage_file = self.reader.open(filepath)
                coverage_addresses = self._extract_coverage_data(coverage_file)

            # save and suppress warnings generated from loading coverage files
            except CoverageParsingError as e:
                errors[CoverageParsingError].append(e)
                continue

            # ensure some data was actually extracted from the log
            if not coverage_addresses:
                errors[CoverageMissingError].append(CoverageMissingError(filepath))
                continue

            # save the attribution data for this coverage data
            for address in coverage_addresses:
                if address in self.metadata.nodes:
                    self.owners[address].add(filepath)

            # aggregate all coverage data into a single set of addresses
            aggregate_addresses.update(coverage_addresses)

        if not aggregate_addresses:
            return (None, errors)

        # optimize the aggregated data (once) and save it to the director
        coverage_data = self._optimize_coverage_data(aggregate_addresses)
        coverage = self.create_coverage(batch_name, coverage_data)

        # evaluate coverage
        if not coverage.nodes:
            errors[CoverageMappingAbsent].append(CoverageMappingAbsent(coverage))
        elif coverage.suspicious:
            errors[CoverageMappingSuspicious].append(CoverageMappingSuspicious(coverage))

        #----------------------------------------------------------------------
        end = time.time()
        logger.debug("Batch loading took %f seconds" % (end-start))

        # return the created coverage name
        return (coverage, errors)

    def load_coverage_files(self, filepaths, progress_callback=logger.debug):
        """
        Create new database coverage mappings from a list of coverage files.

        Returns a tuple of (created_coverage, errors)
        """
        errors = collections.defaultdict(list)
        all_coverage = []

        # unsupress NO_COVERAGE_ERROR per-load, instead of per-session
        self.suppressed_errors.discard(CoverageMissingError)

        start = time.time()
        #----------------------------------------------------------------------

        #
        # stop the director's aggregate set from recomputing after each new
        # coverage mapping is created. instead, we want to wait till *all* new
        # files have been loaded and mapped, computing the new aggregate only
        # at very end. this is far more performant.
        #

        self.suspend_aggregation()

        #
        # loop through the list of filepaths we have been given and begin
        # the process of loading the coverage data from disk, and normalizing
        # it for the director to consume
        #

        for i, filepath in enumerate(filepaths, 1):
            logger.debug("-"*50)
            progress_callback("Loading coverage %u/%u" % (i, len(filepaths)))

            # attempt to load coverage data from disk
            try:
                coverage_file = self.reader.open(filepath)
                coverage_addresses = self._extract_coverage_data(coverage_file)
                coverage_data = self._optimize_coverage_data(coverage_addresses)

            # save and suppress warnings generated from loading coverage files
            except CoverageParsingError as e:
                errors[CoverageParsingError].append(e)
                continue

            # ensure some data was actually extracted from the log
            if not coverage_addresses:
                errors[CoverageMissingError].append(CoverageMissingError(filepath))
                continue

            # save the attribution data for this coverage data
            for address in coverage_data:
                if address in self.metadata.nodes:
                    self.owners[address].add(filepath)

            #
            # request a name for the new coverage mapping that the director will
            # generate from the loaded coverage data
            #

            coverage_name = self._suggest_coverage_name(filepath)
            coverage = self.create_coverage(coverage_name, coverage_data, filepath)

            # evaluate coverage
            if not coverage.nodes:
                errors[CoverageMappingAbsent].append(CoverageMappingAbsent(coverage))
            elif coverage.suspicious:
                errors[CoverageMappingSuspicious].append(CoverageMappingSuspicious(coverage))

            # add the newly created coverage to the list of coverage to be returned
            all_coverage.append(coverage)

        #
        # resume the director's aggregation service, triggering an update to
        # recompute the aggregate set with the newly loaded coverage
        #

        progress_callback("Recomputing coverage aggregate...")
        self.resume_aggregation()

        #----------------------------------------------------------------------
        end = time.time()
        logger.debug("File loading took %f seconds" % (end-start))

        # all done
        return (all_coverage, errors)

    def _extract_coverage_data(self, coverage_file):
        """
        Internal routine to extract relevant coverage data from a CoverageFile.
        """
        database_target = self.metadata.filename
        target_names = [database_target] + self._target_whitelist

        #
        # inspect the coverage file and extract the module name that seems to
        # match the executable loaded by the disassembler (fuzzy lookup) or
        # otherwise aliased by the user through the fallback dialog
        #

        for name in target_names:
            module_name = self._find_fuzzy_name(coverage_file, name)
            if module_name:
                break

        #
        # if the fuzzy name lookup failed and there are named modules in the
        # coverage file, then we will show them to the user and see if they
        # can pick out a matching module to load coverage from
        #

        if not module_name and coverage_file.modules:

            #
            # earlier in this load, the user opted to ignore future attempts
            # to alias or select coverage data. this is useful when trying to
            # load a batch of coverage files, where some coverage files
            # contain data, but none relevant to this database.
            #

            if CoverageMissingError in self.suppressed_errors:
                return []

            #
            # show the module selection dialog to the user, and wait for them
            # to select something, or close the dialog
            #

            dialog = ModuleSelector(database_target, coverage_file.modules, coverage_file.filepath)
            result = dialog.exec_()

            # check if the user opted to ignore future warnings for missing coverage
            if dialog.ignore_missing:
                self.suppressed_errors.add(CoverageMissingError)

            #
            # if the user closed the dialog without selecting a name, there's
            # nothing we can do for them. return an empty set of coverage data
            #

            if not result:
                return []

            # the user selected a module name! use that to extract coverage
            module_name = dialog.selected_name

            # the user opted to save the selected name as an 'alias'
            if dialog.remember_alias:
                self._target_whitelist.append(module_name)

        #
        # (module, offset, size) style logs (eg, drcov)
        #

        imagebase = self.metadata.imagebase

        try:
            coverage_blocks = coverage_file.get_offset_blocks(module_name)
            coverage_addresses = [imagebase+offset for bb_start, bb_len in coverage_blocks for offset in xrange(bb_start, bb_start+bb_len)]
            return coverage_addresses
        except NotImplementedError:
            pass

        #
        # (module, offset) style logs (eg, mod+off)
        #

        try:
            coverage_offsets = coverage_file.get_offsets(module_name)
            coverage_addresses = [imagebase+offset for offset in coverage_offsets]
            return coverage_addresses
        except NotImplementedError:
            pass

        #
        # (absolute address) style log (eg, instruction/bb trace)
        #

        try:
            coverage_addresses = coverage_file.get_addresses(module_name)
            return coverage_addresses
        except NotImplementedError:
            pass

        # well, this one is probably the fault of the CoverageFile author...
        raise NotImplementedError("Incomplete CoverageFile implementation")

    def _optimize_coverage_data(self, coverage_addresses):
        """
        Optimize exploded coverage data to the current metadata cache.
        """
        logger.debug("Optimizing coverage data...")
        addresses = set(coverage_addresses)

        # bucketize the exploded coverage addresses
        instructions = addresses & set(self.metadata.instructions)
        basic_blocks = instructions & viewkeys(self.metadata.nodes)

        if not instructions:
            logger.debug("No mappable instruction addresses in coverage data")
            return []

        """
        #
        # TODO/LOADING: display undefined/misaligned data somehow?
        #

        unknown = addresses - instructions

        # bucketize the uncategorized exploded addresses
        undefined, misaligned = [], []
        for address in unknown:

            # size == -1 (undefined inst)
            if self.metadata.get_instruction_size(address):
                undefined.append(address)

            # size == 0 (misaligned inst)
            else:
                misaligned.append(address)
        """

        #
        # here we attempt to compute the ratio between basic block addresses,
        # and instruction addresses in the incoming coverage data.
        #
        # this will help us determine if the existing instruction data is
        # sufficient, or whether we need to explode/flatten the basic block
        # addresses into their respective child instructions
        #

        block_ratio = len(basic_blocks) / float(len(instructions))
        block_trace_confidence = 0.80
        logger.debug("Block confidence %f" % block_ratio)

        #
        # a low basic block to instruction ratio implies the data is probably
        # from an instruction trace, or a basic block trace has been flattened
        # exploded already (eg, a drcov log)
        #

        if block_ratio < block_trace_confidence:
            logger.debug("Optimized as instruction trace...")
            return list(instructions)

        #
        # take each basic block address, and explode it into a list of all the
        # instruction addresses contained within the basic block as determined
        # by the database metadata cache
        #
        # it is *possible* that this may introduce 'inaccurate' paint should
        # the user provide a basic block trace that crashes mid-block. but
        # that is not something we can account for in a block trace...
        #

        block_instructions = set([])
        for address in basic_blocks:
            block_instructions |= set(self.metadata.nodes[address].instructions)

        logger.debug("Optimized as basic block trace...")
        return list(block_instructions | instructions)

    def _suggest_coverage_name(self, filepath):
        """
        Return a suggested coverage name for the given filepath.
        """
        coverage_name = os.path.basename(filepath)
        coverage = self.get_coverage(coverage_name)

        # no internal conflict, the filename is a unique enough coverage name
        if not coverage:
            return coverage_name

        #
        # if there is an existing coverage mapping under this name, odds are
        # that the user is re-loading the same coverage file in which case the
        # director will overwrite the old DatabaseCoverage object.
        #
        # however, we have to be careful for the case where the user loads a
        # coverage file from a different directory under the same name
        #
        # e.g:
        #  - C:\coverage\foo.log
        #  - C:\coverage\testing\foo.log
        #
        # in these cases, we will append a suffix to the new coverage file
        #

        # assign a suffix to the coverage_name in the event of a collision
        if coverage.filepath != filepath:

            # find a suitable suffix
            for i in xrange(2, 1000000):
                new_name = "%s_%u" % (coverage_name, i)
                if not self.get_coverage(new_name):
                    break

            # save the suffixed name to the return value
            coverage_name = new_name

        # return the suggested coverage name for the given filepath
        return coverage_name

    def _find_fuzzy_name(self, coverage_file, target_name):
        """
        Return the closest matching module name in the given coverage file.
        """
        target_name = target_name.lower()

        #
        # 0. Pre-process module names, strip filepath if present
        #

        clean_module_names = {}
        for module_name_raw in coverage_file.modules:

            # trim 'path' from a 'module name' entry... if present (uncommon)
            module_name = os.path.basename(module_name_raw)

            #
            # if this triggers, it's probably because the coverage file is
            # using full filepaths for 'module names', and that there was
            # two unique filepaths with the same module name, eg:
            #
            #   - C:\foo.dll
            #   - C:\bar\foo.dll
            #
            # this should be super rare, but we'll just revert to using the
            # full / unprocessed paths and bail...
            #

            if module_name in clean_module_names:
                clean_module_names = {name: name for name in coverage_file.modules}
                break

            clean_module_names[module_name] = module_name_raw

        #
        # 1. exact, case-insensitive filename matching
        #

        for module_name in clean_module_names:
            if target_name == module_name.lower():
                return clean_module_names[module_name]

        #
        # 2. exact, case-insensitive filename matching
        #

        for module_name in clean_module_names:
            if target_name == module_name.lower():
                return clean_module_names[module_name]

        #
        # 2. cleave the extension from the target module name (the source)
        # and try again to see if matches anything in the coverage file
        #

        target_name, extension = os.path.splitext(target_name)
        for module_name in clean_module_names:
            if target_name == module_name.lower():
                return clean_module_names[module_name]

        # too risky to do fuzzy matching on short names...
        if len(target_name) < 6:
            return None

        #
        # 3. try to match *{target_name}*{extension} in module_name, assuming
        # target_name is more than 6 characters and there is no other ambiguity
        #

        possible_names = []
        for module_name in clean_module_names:
            if target_name in module_name.lower() and extension in module_name.lower():
                possible_names.append(clean_module_names[module_name])

        # there were no matches on the wildcarding, so we're done
        if not possible_names:
            return None

        #
        # if there is multiple potential matches it is too risky to pick one,
        # so we are not going to return anything as a viable match
        #

        if len(possible_names) > 1:
            return None

        return possible_names[0]

    #----------------------------------------------------------------------
    # Coverage Management
    #----------------------------------------------------------------------

    def get_address_coverage(self, address):
        """
        Return a list of coverage object containing the given address.
        """
        found = []

        for name, db_coverage in iteritems(self._database_coverage):
            if address in db_coverage.coverage:
                found.append(db_coverage)

        return found

    def get_address_file(self, address):
        """
        Return a list of coverage filepaths containing the given address.
        """
        node = self.metadata.get_node(address)
        if not node:
            return []
        return list(self.owners.get(node.address, []))

    def create_coverage(self, coverage_name, coverage_data, coverage_filepath=None):
        """
        Create a new database coverage mapping from the given data.
        """
        return self.update_coverage(coverage_name, coverage_data, coverage_filepath)

    def select_coverage(self, coverage_name):
        """
        Activate a loaded coverage mapping by name.
        """
        logger.debug("Selecting coverage %s" % coverage_name)

        # ensure a coverage mapping actually exists for the given coverage_name
        if not (coverage_name in self.all_names):
            raise ValueError("No coverage matching '%s' was found" % coverage_name)

        # if the given name is already active, there's nothing to do
        if self.coverage_name == coverage_name:
            return

        #
        # save the given coverage_name as the active name. this effectively
        # changes which coverage mapping the director considers active.
        #

        self.coverage_name = coverage_name

        # notify any listeners that we have switched our active coverage
        self._notify_coverage_switched()

    def update_coverage(self, coverage_name, coverage_data, coverage_filepath=None):
        """
        Create or update a databases coverage mapping.
        """
        assert not (coverage_name in RESERVED_NAMES)
        updating_coverage = coverage_name in self.coverage_names

        if updating_coverage:
            logger.debug("Updating coverage %s" % coverage_name)
        else:
            logger.debug("Adding coverage %s" % coverage_name)

        # create a new database coverage mapping from the given coverage data
        new_coverage = DatabaseCoverage(
            self.palette,
            coverage_name,
            coverage_filepath,
            coverage_data
        )
        new_coverage.update_metadata(self.metadata)
        new_coverage.refresh()

        #
        # coverage mapping complete, looks like we're good. commit the new
        # coverage to the director's coverage table and surface it for use.
        #
        # note that this will overwrite an existing coverage mapping present
        # under the same name
        #

        self._commit_coverage(coverage_name, new_coverage)

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

    def _commit_coverage(self, coverage_name, new_coverage):
        """
        Internal add/update of coverage.

        This will automatically update the director's aggregate.
        """

        #
        # if there exists a coverage mapping under the given coverage_name we
        # are trying to add/update, we first must remove anything it has
        # contributed to the aggregate before we dispose of its data
        #

        if coverage_name in self.coverage_names:
            old_coverage = self._database_coverage[coverage_name]
            self.aggregate.subtract_data(old_coverage.data)
            if not self._aggregation_suspended:
                self._refresh_aggregate()

        #
        # this is the critical point where we actually integrate the newly
        # built coverage into the director or replacing an existing entry
        #

        self._database_coverage[coverage_name] = new_coverage

        # (re)-add the newly loaded/updated coverage data to the aggregate
        self.aggregate.add_data(new_coverage.data)
        if not self._aggregation_suspended:
            self._refresh_aggregate()

    def delete_coverage(self, coverage_name):
        """
        Delete a database coverage mapping by name.
        """

        #
        # if the delete request targets the currently active coverage, we want
        # to switch into a safer coverage set to try and avoid any ill effects.
        #

        if coverage_name in [self.coverage_name, AGGREGATE]:
            self.select_coverage(NEW_COMPOSITION)

        # attempt to delete the requested coverage_name
        if coverage_name in self.coverage_names:
            self._delete_user_coverage(coverage_name)
        elif coverage_name == AGGREGATE:
            self._delete_aggregate_coverage()
        else:
            raise ValueError("Cannot delete %s, does not exist" % coverage_name)

        # notify any listeners that we have deleted coverage
        self._notify_coverage_deleted()

    def _delete_user_coverage(self, coverage_name):
        """
        Delete a user created database coverage mapping by name.
        """

        # release the shorthand alias held by this coverage
        self._release_shorthand_alias(coverage_name)

        # remove the database coverage mapping from the director's coverage map
        coverage = self._database_coverage.pop(coverage_name)
        # TODO/FUTURE: check if there's any references to the coverage object?

        # remove the coverage data this mapping contributed to the aggregate
        self.aggregate.subtract_data(coverage.data)
        if not self._aggregation_suspended:
            self._refresh_aggregate()

    def _delete_aggregate_coverage(self):
        """
        Delete the aggregate set, effectively clearing all loaded coverage.
        """

        # loop through all the loaded coverage sets and release them
        for coverage_name in self.coverage_names:
            self._release_shorthand_alias(coverage_name)
            self._database_coverage.pop(coverage_name)
        # TODO/FUTURE: check if there's any references to the coverage aggregate?

        # assign a new, blank aggregate set
        self._special_coverage[AGGREGATE] = DatabaseCoverage(self.palette, AGGREGATE)
        self._refresh_aggregate() # probably not needed

    def get_coverage(self, name):
        """
        Retrieve coverage data for the requested coverage_name.
        """

        # if the given name was an alias, this will dereference it
        coverage_name = self._alias2name.get(name, name)

        # attempt to retrieve the requested coverage
        if coverage_name in self.coverage_names:
            return self._database_coverage[coverage_name]
        if coverage_name in self.special_names:
            return self._special_coverage[coverage_name]

        # could not locate coverage
        return None

    def get_coverage_string(self, coverage_name):
        """
        Retrieve a detailed coverage string for the given coverage_name.
        """

        # special cases that should be static
        if coverage_name == HOT_SHELL or coverage_name == NEW_COMPOSITION:
            return coverage_name

        symbol = self.get_shorthand(coverage_name)
        coverage = self.get_coverage(coverage_name)

        # compute coverage percent & render it in string form
        percent = coverage.instruction_percent*100
        percent_str = "%5.2f" % percent

        #
        # build and return a generic detailed coverage string
        #   eg: 'A - 73.45% - drcov.boombox.exe.03820.0000.proc.log'
        #

        return "%s - %s%% - %s" % (symbol, percent_str, coverage_name)

    def dump_unmapped(self):
        """
        Dump the unmapped coverage data for the active set.
        """
        self.coverage.dump_unmapped()

    #----------------------------------------------------------------------
    # Aliases
    #----------------------------------------------------------------------

    def alias_coverage(self, coverage_name, alias):
        """
        Assign an alias to a loaded database coverage mapping.
        """
        assert not (alias in self.all_names)
        assert not (alias in RESERVED_NAMES)
        self._alias_coverage(coverage_name, alias)

    def _alias_coverage(self, coverage_name, alias):
        """
        Assign alias with no restrictions. Internal use only.
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

        # reduce the coverage's aliases to only shorthand candidates
        try:
            shorthand = self._name2alias[coverage_name] & SHORTHAND_ALIASES
        except KeyError:
            return None

        # there should only ever be one shorthand symbol for a given coverage
        assert len(shorthand) < 2

         # pop the single shorthand symbol (if one is even aliased)
        try:
            return shorthand.pop()
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

        # get the next available symbol (A-Z) from the shorthand pool
        try:
            symbol = self._shorthand.popleft()
        except IndexError:
            return None

        # alias the symbol to the given coverage_name & return it
        self._alias_coverage(coverage_name, symbol)
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

        #
        # in the event that all shorthand aliases have been released back to
        # us, we rest the shorthand list so that new symbols will begin from
        # the start of the alphabet (A, B, C ...)
        #

        if len(self._shorthand) == len(ASCII_SHORTHAND):
            self._shorthand = collections.deque(ASCII_SHORTHAND)

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
        composite_coverage.name = composite_name

        # save the evaluated coverage under the given name
        self._commit_coverage(composite_name, composite_coverage)

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
        Evaluate & cache the given composition (asynchronously).
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

            # get the next coverage expression (an AST) to evaluate
            ast = self._ast_queue.get()
            if ast == None:
                break

            # produce a single composite coverage mapping as described by the AST
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
            return DatabaseCoverage(self.palette)

        #
        # the director's composition evaluation code (this function) is most
        # generally called via the background caching evaluation thread known
        # as self._composition_worker. But this function can also be called
        # inline via the 'add_composition' function from a different thread
        # (namely, the main thread)
        #
        # because of this, we must gate the resources that AST evaluation code
        # operates on behind a lock, restricting the code to one thread.
        #
        # should we call _evaluate_composition from the context of the main
        # thread, it is important that we do so in a pseudo non-blocking way
        # such that we don't hang the UI. await_lock(...) will allow the Qt
        # main thread to yield to other threads while waiting for the lock.
        #

        await_lock(self._composition_lock)

        # recursively evaluate the AST
        composite_coverage = self._evaluate_composition_recursive(ast)

        # map the composited coverage data to the database metadata
        composite_coverage.update_metadata(self.metadata)
        composite_coverage.refresh() # TODO/FUTURE: hash refresh?

        # done operating on shared data (coverage), release the lock
        self._composition_lock.release()

        # return the evaluated composition
        return composite_coverage

    def _evaluate_composition_recursive(self, node):
        """
        The internal (recursive) AST evaluation routine.
        """

        #
        # if the current AST node is a logic operator, we need to evaluate the
        # expressions that make up its input. only once each operand has been
        # concretized is it appropriate for us to operate on them
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
            # before computing a new composition, we first compute a low-cost
            # 'hash' of the desired operation. this hash can be used to
            # identify an existing (eg, previously computed) result, retrieving
            # it from an LRU based cache that holds compositions created by the
            # AST evaluation process.
            #
            # the 'hash' is actually computed as a product of the operator
            # that would normally combine the two coverage sets.
            #
            # for example, when evaluating a coverage composition, the logical
            # operators (eg |, &, ^), it does not matter which side of the
            # equation the coverage components fall on.
            #
            #  eg:
            #      (A | B) == (B | A)
            #
            # while arithmetic operations (-) will produce different results
            #
            #      (A - B) != (B - A)
            #
            # so if we are being asked to compute a composition of (A | B),
            # we first compute:
            #
            #      composition_hash = hash(A) | hash(B)
            #
            # using the composition_hash, we can check the LRU cache for a
            # previous computation of the composition (A | B).
            #
            # the possibility of collisions are generally higher with this
            # form of 'hash', but I still expect them to be extremely rare...
            #

            composition_hash = node.operator(op1.coverage_hash, op2.coverage_hash)

            #
            # evaluating an AST produces lots of 'transient' compositions. To
            # mitigate unnecessary re-computation, we maintain a small LRU cache
            # of these compositions to draw from during subsequent evaluations.
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
            # in the example above, COMP_3 is the final evaluated result that
            # will be returned to the user, while COMP_1/COMP_2 would normally
            # be discarded. Instead, we cache all of these compositions
            # (1, 2, 3) as they may be useful to us in future evaluations.
            #
            # later, if the user then choses to evaluate (A | B) - (Z | D), our
            # cache can retrieve the fully computed (A | B) composition
            # assuming it has not been evicted.
            #
            # this makes Lighthouse far more performant for repeated operations
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
            # now that we have computed the requested coverage mask (a bitmap),
            # we use the mask to generate a new DatabaseCoverage mapping.
            #

            new_composition = DatabaseCoverage(self.palette, data=coverage_mask)

            # cache & return the newly computed composition
            self._composition_cache[composition_hash] = new_composition
            return new_composition

        #
        # if the current AST node is a coverage token, we need simply need to
        # return its associated DatabaseCoverage.
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

        Returns an existing database coverage mapping.
        """
        assert isinstance(coverage_token, TokenCoverageSingle)
        return self.get_coverage(self._alias2name[coverage_token.symbol])

    #----------------------------------------------------------------------
    # Refresh
    #----------------------------------------------------------------------

    def refresh(self):
        """
        Complete refresh of the director and mapped coverage.
        """
        if disassembler[self.metadata.lctx].busy:
            disassembler.warning("Cannot refresh Lighthouse while the disassembler is busy...")
            return

        disassembler.show_wait_box("Refreshing Lighthouse...")
        self._refresh()
        disassembler.hide_wait_box()

    @catch_errors
    def _refresh(self):
        """
        Internal refresh routine, wrapped to help catch bugs for now.
        """

        #
        # (re) build our metadata cache of the underlying database
        #

        if not is_mainthread():
            self.metadata.refresh(metadata_progress)

        #
        # NOTE: optionally, we call the async vesrion here so that we do not pin
        # the mainthread for disassemblers that will primarily read from the
        # database in a background thread (eg, Binja)
        #
        # for example, this refresh action may be called from a UI event or
        # clicking 'Open Coverage Overview' (eg, the mainthread). if we pin
        # the mainthread while doing database reads from a background thread,
        # we cannot post UI updates such as progress updates to the user
        #
        # using an async refresh allows us to 'softly' spin the main (UI)
        # thread and get UI updates while the refresh runs
        #

        else:
            future = self.metadata.refresh_async(metadata_progress, force=True)
            self.metadata.go_synchronous()
            await_future(future)

        # (re) map each set of loaded coverage data to the database
        if self.coverage_names:
            self._refresh_database_coverage()

        # notify of full-refresh
        self._notify_refreshed()

    def refresh_theme(self):
        """
        Refresh UI facing elements to reflect the current theme.

        Does not require @disassembler.execute_ui decorator as no Qt is touched.
        """
        for coverage in self._database_coverage.values():
            coverage.refresh_theme()
        for coverage in self._special_coverage.values():
            coverage.refresh_theme()

    def _refresh_database_coverage(self):
        """
        Refresh all the database coverage mappings managed by the director.
        """
        logger.debug("Refreshing database coverage mappings")

        for i, name in enumerate(self.all_names, 1):
            logger.debug(" - %s" % name)
            disassembler.replace_wait_box(
                "Refreshing coverage mapping %u/%u" % (i, len(self.all_names))
            )
            coverage = self.get_coverage(name)
            coverage.update_metadata(self.metadata)
            coverage.refresh()

    def _refresh_aggregate(self):
        """
        Refresh the aggregate database coverage mapping.
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
