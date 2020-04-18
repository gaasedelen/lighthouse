import time
import bisect
import logging
import weakref
import itertools
import threading
import collections

from lighthouse.util.misc import *
from lighthouse.util.python import *
from lighthouse.util.disassembler import disassembler

from lighthouse.util.debug import catch_errors

logger = logging.getLogger("Lighthouse.Metadata")

#------------------------------------------------------------------------------
# Metadata
#------------------------------------------------------------------------------
#
#    To aid in performance, Lighthouse lifts and indexes an in-memory limited
#    representation of the disassembler's open database. This is commonly
#    referred to as 'metadata' throughout this codebase.
#
#    Once built, the lifted metadata cache stands completely independent of
#    the disassembler. This effectively eliminates the need for Lighthouse to
#    communicate with the underlying disassembler / API (which is slow) when
#    mapping coverage, or doing coverage composition logic.
#
#    With this model, we have been able to move the heavy director based
#    coverage composition logic to python-only threads without disrupting the
#    user, or IDA. (added in v0.4.0)
#
#    However, there are two main caveats of this model -
#
#    1. The cached 'metadata' representation may not always be true to state
#       of the database. For example, if the user defines/undefines functions,
#       the metadata cache will not be aware of such changes.
#
#       Lighthouse will try to update the director's metadata cache when
#       applicable, but there are instances when it will be in the best
#       interest of the user to manually trigger a refresh of the metadata.
#
#    2. Building the metadata comes with an upfront cost, but this cost has
#       been reduced as much as possible. For example, generating metadata for
#       a larger database with ~25k functions, ~725k nodes (basic blocks), and
#       ~3.4m instructions took ~27 seconds.
#
#       This will be negligible for small-medium sized databases, but will be
#       measurable for larger databases.
#
#    Ultimately, this model provides us a more responsive user experience at
#    the expense of the occasional inaccuracies that can be corrected by
#    reasonably low cost refresh.
#

#------------------------------------------------------------------------------
# Database Metadata
#------------------------------------------------------------------------------

class DatabaseMetadata(object):
    """
    Database level metadata cache.
    """

    def __init__(self, lctx=None):
        self.lctx = lctx

        # name & imagebase of the executable this metadata is based on
        self.filename = ""
        self.imagebase = BADADDR

        # database metadata cache status
        self.cached = False

        # the cache of key database structures
        self.nodes = {}
        self.functions = {}
        self.instructions = []

        # internal members to help index & navigate the cached metadata
        self._name2func = {}
        self._node2func = collections.defaultdict(list)
        self._node_addresses = []
        self._function_addresses = []

        # HACK: dirty hack since we can't create a blank node easily
        self._last_node = lambda: None
        self._last_node.instructions = []

        # create the disassembler hooks to listen for rename events
        if lctx:
            self._rename_hooks = disassembler[lctx].create_rename_hooks()
            self._rename_hooks.name_changed = self._name_changed
        else:
            self._rename_hooks = None

        # asynchronous metadata collection thread
        self._refresh_worker = None
        self._stop_threads = False
        self._go_synchronous = False

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------

        self._metadata_modified_callbacks = []
        self._function_renamed_callbacks = []
        self._rebased_callbacks = []

    #--------------------------------------------------------------------------
    # Subsystem Lifetime
    #--------------------------------------------------------------------------

    def start(self):
        """
        Start the metadata subsystem.
        """
        pass # TODO: rebase scheduled task

    def terminate(self):
        """
        Cleanup & terminate the metadata object.
        """
        self.abort_refresh(join=True)
        if self._rename_hooks:
            self._rename_hooks.unhook()

        # best effort to free up resources & improve interpreter spindown
        del self._metadata_modified_callbacks
        del self._function_renamed_callbacks
        del self._rebased_callbacks
        self._clear_cache()

    #--------------------------------------------------------------------------
    # Providers
    #--------------------------------------------------------------------------

    def get_instructions_slice(self, start_address, end_address):
        """
        Get the instructions addresses that fall within a given range.
        """
        index_start = bisect.bisect_left(self.instructions, start_address)
        index_end   = bisect.bisect_left(self.instructions, end_address)
        return self.instructions[index_start:index_end]

    def get_instruction_size(self, address):
        """
        Get the size of an instruction at a given address.

        Returns:
          -1 if undefined address (not within a basic block)
           0 if within defined instruction
           n if it is a defined instruction
        """
        node_metadata = self.get_node(address)

        #
        # if the given address does not fall within a node, we have no idea how
        # big it really is. return -1
        #

        if not node_metadata:
            return -1

        #
        # if the address falls within a node, attempt to return the size of the
        # instruction at its address. if the address is misaligned / in the
        # middle of an instruction, simply return 0
        #

        return node_metadata.instructions.get(address, 0)

    def get_node(self, address):
        """
        Get the node (basic block) metadata for a given address.
        """

        # fast path, effectively a LRU cache of 1 ;P
        if address in self._last_node.instructions:
            return self._last_node

        #
        # use the lookup lists to do a 'fuzzy' lookup of the given address,
        # locating the index of the closest known node address (rounding down)
        #

        index = bisect.bisect_right(self._node_addresses, address) - 1
        node_metadata = self.nodes.get(self._node_addresses[index], None)

        #
        # this should hit 99.9% of the time on the first index...
        #
        # but we added a fallback in the rare case when binja creates an edge
        # to an unknown/undefined instruction, whose address happens to fall
        # within a real one, thus throwing off the basic block lookup...
        #
        # technically, we could also fail going back only one block, but at
        # that point, idc, the user is looking at some weird binaries... :\
        #

        if not (node_metadata and address in node_metadata.instructions):
            node_metadata = self.nodes.get(self._node_addresses[index-1], None)

            # double fault, let's just dip...
            if not (node_metadata and address in node_metadata.instructions):
                return None

        #
        # if the selected node metadata contains the given target address, it
        # is a positive hit and we should cache this node (in last_node) for
        # faster consecutive lookups
        #

        self._last_node = node_metadata

        # return the located node_metadata
        return node_metadata

    def get_function(self, function_address):
        """
        Get the function metadata that starts at the given address.
        """
        return self.functions.get(function_address, None)

    def get_functions_containing(self, address):
        """
        Get the list of function metadata objects that contain the given address.
        """
        node_metadata = self.get_node(address)
        if not node_metadata:
            return []
        return self.get_functions_by_node(node_metadata.address)

    def get_function_by_name(self, function_name):
        """
        Get the function metadata for a given function name.
        """
        try:
            return self.functions[self._name2func[function_name]]
        except (IndexError, KeyError):
            return None

    def get_function_by_index(self, index):
        """
        Get the function metadata for a given function index.
        """
        try:
            return self.functions[self._function_addresses[index]]
        except (IndexError, KeyError):
            return None

    def get_function_index(self, address):
        """
        Get the function index for a given address.
        """
        return self._function_addresses.index(address)

    def get_functions_by_node(self, node_address):
        """
        Get the functions containing the given node.
        """
        return self._node2func.get(node_address, [])

    def get_closest_function(self, address):
        """
        Get the function metadata for the function closest to the give address.
        """

        # sanity check
        if not self._function_addresses:
            return None

        # get the closest insertion point of the given address
        index = bisect.bisect_left(self._function_addresses, address)

        # the given address is a min, return the first known function
        if index == 0:
            return self.functions[self._function_addresses[0]]

        # given address is a max, return the last known function
        if index == len(self._function_addresses):
            return self.functions[self._function_addresses[-1]]

        # select the two candidate addresses
        before = self._function_addresses[index - 1]
        after  = self._function_addresses[index]

        # return the function closest to the given address
        if after - address < address - before:
            return self.functions[after]
        else:
            return self.functions[before]

    def is_big(self):
        """
        Return a bool indicating whether we think the database is 'big'.
        """
        return len(self.functions) > 50000

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    def refresh(self, progress_callback=None):
        """
        Refresh the database metadata cache.
        """
        self._refresh(progress_callback)

    def refresh_async(self, progress_callback=None, force=False):
        """
        Refresh the database metadata cache asynchronously.

        Returns a future (Queue) that will carry the completion message.
        """
        assert self._refresh_worker == None, 'Refresh already running'
        result_queue = queue.Queue()

        #
        # if there is already metadata cached for this disassembler session,
        # ignore a request to refresh it unless forced
        #

        if self.cached and not force:
            result_queue.put(False)
            return result_queue

        #
        # reset the async abort and go_synchronous flags so that we can use them
        # for this new refresh if needed
        #

        self._stop_threads = False
        self._go_synchronous = False

        #
        # kick off an asynchronous metadata collection task
        #

        self._refresh_worker = threading.Thread(
            target=self._refresh_async,
            args=(result_queue, progress_callback,)
        )
        self._refresh_worker.start()

        #
        # immediately return a queue to the caller which it can use to listen
        # on and wait for a refresh completion message
        #

        return result_queue

    def abort_refresh(self, join=False):
        """
        Abort an asynchronous refresh.

        To guarantee an asynchronous refresh has been canceled, the caller can
        optionally wait for the result_queue from refresh() to return 'None'.

        Alternatively, the `join` parameter can be set to `True`, making this
        function block until the refresh is canceled.
        """

        #
        # the refresh worker (if it exists) can be ripped away at any time.
        # take a local reference to avoid a double fetch problems
        #

        worker = self._refresh_worker

        #
        # if there is no worker present or running (cleaning up?) there is
        # nothing for us to abort. Simply reset the abort flag (just in case)
        # and return immediately
        #

        if not (worker and worker.is_alive()):
            self._stop_threads = False
            self._refresh_worker = None
            return

        # signal the worker thread to stop
        self._stop_threads = True

        # if requested, don't return until the worker thread has stopped...
        if join:
            worker.join()

    def _refresh_instructions(self):
        """
        Refresh the list of database instructions (from function metadata).
        """
        instructions = []
        for function_metadata in itervalues(self.functions):
            instructions.append(function_metadata.instructions)
        instructions = list(set(itertools.chain.from_iterable(instructions)))
        instructions.sort()

        # commit the updated instruction list
        self.instructions = instructions

    def _refresh_lookup(self):
        """
        Refresh the internal fast lookup address lists.

        Fast lookup lists are simply sorted address lists of function metadata,
        node metadata, or possibly other forms of metadata (in the future). We
        create sorted lists of metadata object addresses so that we can use them
        for fast, fuzzy address lookup (eg, bisect).

         c.f:
          - get_node(ea)
          - get_function(ea)

        """
        self._last_node = lambda: None # XXX blank node hack, see other ref to _last_node
        self._last_node.instructions = []
        self._name2func = { f.name: f.address for f in itervalues(self.functions) }
        self._node_addresses = sorted(self.nodes.keys())
        self._function_addresses = sorted(self.functions.keys())
        for function_metadata in itervalues(self.functions):
            for node_address in function_metadata.nodes:
                self._node2func[node_address].append(function_metadata)

    def go_synchronous(self):
        """
        Switch an ongoing async refresh into a synchronous one.

        This will make it go ... significantly faster ... but cannot be interrupted.
        """
        self._go_synchronous = True

    #--------------------------------------------------------------------------
    # Metadata Collection
    #--------------------------------------------------------------------------

    @not_mainthread
    def _refresh_async(self, result_queue, progress_callback=None):
        """
        Internal thread worker routine to refresh the database metadata asynchronously.
        """

        # start an interruptable refresh
        completed = self._refresh(progress_callback, True)

        # clean up our thread's reference as it is basically done/dead
        self._refresh_worker = None

        # send the refresh result (good/bad) incase anyone is still listening
        result_queue.put(completed)

        # exit thread...

    def _clear_cache(self):
        """
        Cleare the metadata cache of all collected info.
        """
        self.nodes = {}
        self.functions = {}
        self.instructions = []
        self._node2func = collections.defaultdict(list)
        self._refresh_lookup()
        self.cached = False

    def _refresh(self, progress_callback=None, is_async=False):
        """
        Internal routine that will update the database metadata cache.
        """
        self._clear_cache()

        # pause our rename listening hooks (more performant collection)
        if self._rename_hooks:
            self._rename_hooks.unhook()

        # grab the cached imagebase as it might have changed
        prev_imagebase = self.imagebase

        # refresh high level database properties that we wish to cache
        self._sync_refresh_properties()

        #
        # we will perform a complete metadata refresh of all database defined
        # functions. let's retrieve that list from the disassembler now...
        #

        disassembler_ctx = disassembler[self.lctx]
        function_addresses = disassembler.execute_read(disassembler_ctx.get_function_addresses)()
        total = len(function_addresses)

        start = time.time()
        #----------------------------------------------------------------------

        # refresh the core database metadata asynchronously
        if is_async and self._async_collect_metadata(function_addresses, progress_callback):
            self._clear_cache()
            return False

        # refresh the core database metadata synchronously
        completed = total - len(function_addresses)
        self._sync_collect_metadata(function_addresses, progress_callback, completed)

        #----------------------------------------------------------------------
        end = time.time()
        logger.debug("Metadata collection took %s seconds" % (end - start))

        # regenerate the instruction list from collected metadata
        self._refresh_instructions()

        # refresh the internal function/node fast lookup lists
        self._refresh_lookup()

        #----------------------------------------------------------------------

        # reinstall the rename listener hooks now that the refresh is done
        self._rename_hooks.hook()

        # the metadata refresh is effectively done, and the data is now 'cached'
        self.cached = True

        # detect & notify of a rebase event
        if prev_imagebase != BADADDR and prev_imagebase != self.imagebase:
            self._notify_rebased(prev_imagebase, self.imagebase)

        # return true/false to indicates completion
        return True

    @disassembler.execute_read
    def _sync_refresh_properties(self):
        """
        Refresh a selection of interesting database properties.
        """
        disassembler_ctx = disassembler[self.lctx]
        self.filename = disassembler_ctx.get_root_filename()
        self.imagebase = disassembler_ctx.get_imagebase()

    @disassembler.execute_read
    def _sync_collect_metadata(self, function_addresses, progress_callback, progress_base=0):
        """
        Collect metadata from the underlying database.
        """
        CHUNK_SIZE = 500
        completed = progress_base
        total = progress_base + len(function_addresses)
        logger.debug("Refreshing synchronously from %u/%u" % (completed, total))

        while function_addresses:

            # split off a chunk of functions to process metadata for
            addresses_chunk = function_addresses[:CHUNK_SIZE]
            del function_addresses[:CHUNK_SIZE]

            # collect metadata from the database
            self._cache_functions(addresses_chunk)

            # report incremental progress to an optional progress_callback
            if progress_callback:
                completed += CHUNK_SIZE if function_addresses else len(addresses_chunk)
                progress_callback(completed, total)

    @not_mainthread
    def _async_collect_metadata(self, function_addresses, progress_callback):
        """
        Collect metadata from the underlying database asynchronously (interruptable).
        """
        CHUNK_SIZE = 150
        completed = 0
        total = len(function_addresses)
        logger.debug("Refreshing asynchronously from %u/%u" % (completed, total))

        while function_addresses:

            #
            # here we will split off CHUNK_SIZE elements from the function
            # addresses list, in-place. this allows the list to keep track of
            # what has not been processed, such that the caller can continue
            # to operate on it if needed
            #

            addresses_chunk = function_addresses[:CHUNK_SIZE]
            del function_addresses[:CHUNK_SIZE]

            # collect metadata from the database
            self._async_cache_functions(addresses_chunk)

            # report incremental progress to an optional progress_callback
            if progress_callback:
                completed += CHUNK_SIZE if function_addresses else len(addresses_chunk)
                progress_callback(completed, total)

            # if the refresh was canceled, stop collecting metadata and bail
            if self._stop_threads:
                logger.debug("Async metadata collection is bailing!")
                return True

            # ALL SYSTEMS GO!!
            if self._go_synchronous:
                break

            # sleep some so we don't choke the mainthread
            time.sleep(.015)

        # the refresh either completed, or it is going synchronous!
        return False

    @disassembler.execute_read
    def _async_cache_functions(self, addresses_chunk):
        """
        Wrapped version of self._cache_functions, safe for use from an async worker thread.
        """
        self._cache_functions(addresses_chunk)

    @catch_errors
    def _cache_functions(self, addresses_chunk):
        """
        Lift and cache function metadata for the given list of function addresses.
        """
        disassembler_ctx = disassembler[self.lctx]

        for address in addresses_chunk:

            # attempt to 'lift' the function from the database
            try:
                function_metadata = FunctionMetadata(address, disassembler_ctx)

            #
            # this is not exactly a good thing but it indicates that the
            # disassembler didn't see the a function that we thought should
            # have been there based on what it told us previously...
            #
            # this means the database might have changed, while the refresh
            # was running. it's not the end of the world, but it might mean
            # the cache will not be fully accurate...
            #

            except Exception:
                lmsg(" - Caching function at 0x%08X failed..." % address)
                logger.exception("FunctionMetadata Error:")
                continue

            # add the updated info
            self.nodes.update(function_metadata.nodes)
            self.functions[address] = function_metadata

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _name_changed(self, address, new_name):
        """
        Handle function rename event.
        """
        function = self.get_function(address)
        if not (function and function.address == address):
            return

        # if the name isn't actually changing (misfire?) nothing to do
        if new_name == function.name:
            return

        logger.debug("Name changing @ 0x%X" % address)
        logger.debug("  Old name: %s" % function.name.encode("utf-8"))
        logger.debug("  New name: %s" % new_name.encode("utf-8"))

        # update the function name in the cached lookup & rename it for real
        self._name2func[new_name] = self._name2func.pop(function.name)
        function.name = new_name

        # notify metadata listeners of the rename event
        self._notify_function_renamed()

    #--------------------------------------------------------------------------
    # Callbacks
    #--------------------------------------------------------------------------

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

    def function_renamed(self, callback):
        """
        Subscribe a callback for function rename events.
        """
        register_callback(self._function_renamed_callbacks, callback)

    def _notify_function_renamed(self):
        """
        Notify listeners of a function rename event.
        """
        notify_callback(self._function_renamed_callbacks)

    def rebased(self, callback):
        """
        Subscribe a callback for director rebasing events.
        """
        register_callback(self._rebased_callbacks, callback)

    def _notify_rebased(self, old_imagebase, new_imagebase):
        """
        Notify listeners of a database rebasing event.

        TODO/FUTURE: send old / new imagebases
        """
        notify_callback(self._rebased_callbacks)

#------------------------------------------------------------------------------
# Function Metadata
#------------------------------------------------------------------------------

class FunctionMetadata(object):
    """
    Function level metadata cache.
    """

    def __init__(self, address, disassembler_ctx=None):

        # function metadata
        self.address = address
        self.name = None

        # node metadata
        self.nodes = {}
        self.edges = collections.defaultdict(list)

        # fixed/baked/computed metrics
        self.size = 0
        self.node_count = 0
        self.edge_count = 0
        self.instruction_count = 0
        self.cyclomatic_complexity = 0

        # collect metdata from the underlying database
        self._cache_function(disassembler_ctx)

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def instructions(self):
        """
        Return the instruction addresses in this function.
        """
        return set(itertools.chain.from_iterable([node.instructions for node in itervalues(self.nodes)]))

    @property
    def empty(self):
        """
        Return a bool indicating whether the object is populated.
        """
        return self.size == 0

    #--------------------------------------------------------------------------
    # Metadata Population
    #--------------------------------------------------------------------------

    def _cache_function(self, disassembler_ctx):
        """
        Collect function metadata from the underlying database.
        """
        self.name = disassembler_ctx.get_function_name_at(self.address)
        self._refresh_nodes(disassembler_ctx)
        self._finalize()

    def _refresh_nodes(self, disassembler_ctx):
        """
        This will be replaced with a disassembler-specific function at runtime.

        NOTE: Read the 'MONKEY PATCHING' section at the end of this file.
        """
        raise RuntimeError("This function should have been monkey patched...")

    def _ida_refresh_nodes(self, _):
        """
        Refresh function node metadata against an open IDA database.
        """
        function_metadata = self
        function_metadata.nodes = {}

        # get function & flowchart object from IDA database
        function  = idaapi.get_func(self.address)
        flowchart = idaapi.qflow_chart_t("", function, idaapi.BADADDR, idaapi.BADADDR, 0)

        #
        # now we will walk the flowchart for this function, collecting
        # information on each of its nodes (basic blocks) and populating
        # the function & node metadata objects.
        #

        for node_id in xrange(flowchart.size()):
            node = flowchart[node_id]

            #
            # the node current node appears to have a size of zero. This means
            # that another flowchart / function owns this node so we can just
            # ignore it...
            #

            if node.start_ea == node.end_ea:
                continue

            # create a new metadata object for this node
            node_metadata = NodeMetadata(node.start_ea, node.end_ea, node_id)

            #
            # establish a relationship between this node (basic block) and
            # this function metadata (its parent)
            #

            function_metadata.nodes[node.start_ea] = node_metadata

        # compute all of the edges between nodes in the current function
        for node_metadata in itervalues(function_metadata.nodes):
            edge_src = node_metadata.edge_out
            for edge_dst in idautils.CodeRefsFrom(edge_src, True):
                if edge_dst in function_metadata.nodes:
                    function_metadata.edges[edge_src].append(edge_dst)

    def _binja_refresh_nodes(self, disassembler_ctx):
        """
        Refresh function node metadata against an open Binary Ninja database.
        """
        function_metadata = self
        function_metadata.nodes = {}
        bv = disassembler_ctx.bv

        # get the function from the Binja database
        function = bv.get_function_at(self.address)

        #
        # now we will walk the flowchart for this function, collecting
        # information on each of its nodes (basic blocks) and populating
        # the function & node metadata objects.
        #

        for node in function.basic_blocks:

            # create a new metadata object for this node
            node_metadata = NodeMetadata(node.start, node.end, node.index, disassembler_ctx)

            #
            # establish a relationship between this node (basic block) and
            # this function metadata (its parent)
            #

            function_metadata.nodes[node.start] = node_metadata

            #
            # enumerate the edges produced by this node (basic block) with a
            # destination that falls within this function.
            #

            edge_src = node_metadata.edge_out

            count = ctypes.c_ulonglong(0)
            edges = core.BNGetBasicBlockOutgoingEdges(node.handle, count)

            for i in range(0, count.value):
                if edges[i].target:
                    function_metadata.edges[edge_src].append(node._create_instance(core.BNNewBasicBlockReference(edges[i].target), bv).start)
            core.BNFreeBasicBlockEdgeList(edges, count.value)

            # NOTE/PERF ~28% of metadata collection time alone...
            #for edge in node.outgoing_edges:
            #    function_metadata.edges[edge_src].append(edge.target.start)

    def _compute_complexity(self):
        """
        Walk the function CFG to determine approximate cyclomatic complexity.

        The purpose of this function is mostly to account for IDA's inclusion
        of additional floating nodes in function flowcharts. These blocks tend
        to be for exception handlers, but can manifest in various other cases.

        By walking the function CFG, we can identify these 'disembodied'
        blocks that have no incoming edge and ignore them in our cyclomatic
        complexity calculation. Not doing so will radically throw off the
        cyclomatic complexity score.
        """
        confirmed_nodes = set()
        confirmed_edges = {}

        #
        # to_walk contains a list of node addresses. we draw from this list
        # one at a time, walking across all of the outgoing edges from the
        # current node (node_address) to walk the function graph
        #

        to_walk = set([self.address]) if self.nodes else set()
        while to_walk:

            # this is the address of the node we will 'walk' from
            node_address = to_walk.pop()
            confirmed_nodes.add(node_address)

            # now we loop through all edges that originate from this block
            current_src = self.nodes[node_address].edge_out
            for current_dest in self.edges[current_src]:

                # ignore nodes we have already visited
                if current_dest in confirmed_nodes:
                    continue

                #
                # it appears that this node has not been visited yet, so we
                # will want to walk its edges sometime soon to continue the
                # graph exploration
                #

                to_walk.add(current_dest)

            # update the map of confirmed (walked) edges
            confirmed_edges[current_src] = self.edges.pop(current_src)

        # compute the final cyclomatic complexity for the function
        num_edges = sum(len(x) for x in itervalues(confirmed_edges))
        num_nodes = len(confirmed_nodes)
        return num_edges - num_nodes + 2

    def _finalize(self):
        """
        Finalize function metadata for use.
        """
        self.size = sum(node.size for node in itervalues(self.nodes))
        self.node_count = len(self.nodes)
        self.edge_count = len(self.edges)
        self.instruction_count = sum(node.instruction_count for node in itervalues(self.nodes))
        self.cyclomatic_complexity = self._compute_complexity()

    #--------------------------------------------------------------------------
    # Operator Overloads
    #--------------------------------------------------------------------------

    def __eq__(self, other):
        """
        Compute function metadata equality (==)
        """
        result = True
        result &= self.name == other.name
        result &= self.size == other.size
        result &= self.address == other.address
        result &= self.node_count == other.node_count
        result &= self.instruction_count == other.instruction_count
        result &= viewkeys(self.nodes) == viewkeys(other.nodes)
        return result

#------------------------------------------------------------------------------
# Node Metadata
#------------------------------------------------------------------------------

class NodeMetadata(object):
    """
    Node (basic block) level metadata cache.
    """

    def __init__(self, start_ea, end_ea, node_id=None, disassembler_ctx=None):

        # node metadata
        self.size = end_ea - start_ea
        self.address = start_ea
        self.instruction_count = 0
        self.edge_out = -1

        # flowchart node_id
        self.id = node_id

        # instruction addresses
        self.instructions = {}

        #----------------------------------------------------------------------

        # collect metadata from the underlying database
        self._cache_node(disassembler_ctx)

    #--------------------------------------------------------------------------
    # Metadata Population
    #--------------------------------------------------------------------------

    def _cache_node(self, disassembler_ctx):
        """
        This will be replaced with a disassembler-specific function at runtime.

        NOTE: Read the 'MONKEY PATCHING' section at the end of this file.
        """
        raise RuntimeError("This function should have been monkey patched...")

    def _ida_cache_node(self, _):
        """
        Collect node metadata from the underlying database.
        """
        current_address = self.address
        node_end = self.address + self.size

        #
        # loop through the node's entire address range and count its
        # instructions. Note that we are assuming that every defined
        # 'head' (in IDA) is an instruction
        #

        while current_address < node_end:
            instruction_size = idaapi.get_item_end(current_address) - current_address
            self.instructions[current_address] = instruction_size
            current_address += instruction_size

        # the source of the outward edge
        self.edge_out = current_address - instruction_size

        # save the number of instructions in this block
        self.instruction_count = len(self.instructions)

    def _binja_cache_node(self, disassembler_ctx):
        """
        Collect node metadata from the underlying database.
        """
        current_address = self.address
        node_end = self.address + self.size

        # NOTE/PERF: gotta go fast :D
        bh = disassembler_ctx.bv.handle
        ah = disassembler_ctx.bv.arch.handle

        #
        # Note that we 'iterate over' the instructions using their byte length
        # because it is far more performant than Binary Ninja's instruction
        # generators which also produce instruction text, tokens etc...
        #

        while current_address < node_end:
            instruction_size = core.BNGetInstructionLength(bh, ah, current_address) or 1
            self.instructions[current_address] = instruction_size
            current_address += instruction_size

        # the source of the outward edge
        self.edge_out = current_address - instruction_size

        # save the number of instructions in this block
        self.instruction_count = len(self.instructions)

    #--------------------------------------------------------------------------
    # Operator Overloads
    #--------------------------------------------------------------------------

    def __str__(self):
        """
        Printable NodeMetadata.
        """
        output  = ""
        output += "Node 0x%08X Info:\n" % self.address
        output += " Address: 0x%08X\n" % self.address
        output += " Size: %u\n" % self.size
        output += " Instruction Count: %u\n" % self.instruction_count
        output += " Id: %u\n" % self.id
        output += " Instructions: %s" % self.instructions
        return output

    def __contains__(self, address):
        """
        Overload python's 'in' keyword for this object.

        This allows us to use `in` to check if an address falls within a node.
        """
        if self.address <= address < self.address + self.size:
            return True
        return False

    def __eq__(self, other):
        """
        Compute node equality (==)
        """
        result = True
        result &= self.size == other.size
        result &= self.address == other.address
        result &= self.instruction_count == other.instruction_count
        result &= self.id == other.id
        return result

#------------------------------------------------------------------------------
# Async Metadata Helpers
#------------------------------------------------------------------------------

@disassembler.execute_ui
def metadata_progress(completed, total):
    """
    Handler for metadata collection callback, updates progress dialog.
    """
    disassembler.replace_wait_box(
        "Collected metadata for %u/%u Functions" % (completed, total)
    )

#------------------------------------------------------------------------------
# MONKEY PATCHING
#------------------------------------------------------------------------------
#
#   We use 'monkey patching' to modify the Metadata class definitions at
#   runtime. Specifically, we use it to swap in metadata collection routines
#   that have been carefully tailored for a given disassembler.
#
#   The reason for this is that the metadata collection code is very
#   disassembler-specific, and that it needs to be as performant as possible.
#   Shimming metadata collection code to be disassembler agnostic is going
#   to be messy and slow.
#

if disassembler.NAME == "IDA":
    import idaapi
    import idautils
    FunctionMetadata._refresh_nodes = FunctionMetadata._ida_refresh_nodes
    NodeMetadata._cache_node = NodeMetadata._ida_cache_node

elif disassembler.NAME == "BINJA":
    import ctypes
    import binaryninja
    from binaryninja import core
    FunctionMetadata._refresh_nodes = FunctionMetadata._binja_refresh_nodes
    NodeMetadata._cache_node = NodeMetadata._binja_cache_node

else:
    raise NotImplementedError("DISASSEMBLER-SPECIFIC SHIM MISSING")
