import time
import Queue
import bisect
import logging
import weakref
import threading
import collections

from lighthouse.util.misc import *
from lighthouse.util.disassembler import disassembler

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
#       a database with ~17k functions, ~95k nodes (basic blocks), and ~563k
#       instructions takes only ~6 seconds.
#
#       This will be negligible for small-medium sized databases, but may still
#       be jarring for larger databases.
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

    def __init__(self):

        # name & imagebase of the executable this metadata is based on
        self.filename = ""
        self.imagebase = -1

        # database metadata cache status
        self.cached = False

        # the cache of key database structures
        self.nodes = {}
        self.functions = {}
        self.instructions = []

        # internal members to help index & navigate the cached metadata
        self._stale_lookup = False
        self._name2func = {}
        self._last_node = []           # HACK: blank iterable for now
        self._node_addresses = []
        self._function_addresses = []

        # placeholder attribute for disassembler event hooks
        self._rename_hooks = None

        # metadata callbacks (see director for more info)
        self._function_renamed_callbacks = []

        # asynchronous metadata collection thread
        self._refresh_worker = None
        self._stop_threads = False

    def terminate(self):
        """
        Cleanup & terminate the metadata object.
        """
        self.abort_refresh(join=True)
        if self._rename_hooks:
            self._rename_hooks.unhook()

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

    def get_node(self, address):
        """
        Get the node (basic block) metadata for a given address.
        """
        assert not self._stale_lookup, "Stale metadata is unsafe to use..."

        # fast path, effectively a LRU cache of 1 ;P
        if address in self._last_node:
            return self._last_node

        #
        # use the lookup lists to do a 'fuzzy' lookup of the given address,
        # locating the index of the closest known node address (rounding down)
        #

        index = bisect.bisect_right(self._node_addresses, address) - 1
        node_metadata = self.nodes.get(self._node_addresses[index], None)

        #
        # if the given address does not fall within the selected node (or the
        # node simply does not exist), then we have no match/metadata to return
        #

        if not (node_metadata and address in node_metadata):
            return None

        #
        # if the selected node metadata contains the given target address, it
        # is a positive hit and we should cache this node (in last_node) for
        # faster consecutive lookups
        #

        self._last_node = node_metadata

        # return the located node_metadata
        return node_metadata

    def get_function(self, address):
        """
        Get the function metadata for a given address.
        """
        node_metadata = self.get_node(address)
        if not node_metadata:
            return None
        return node_metadata.function

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

    def flatten_blocks(self, basic_blocks):
        """
        Flatten a list of basic blocks (address, size) to instruction addresses.

        This function provides a way to convert a list of (address, size) basic
        block entries into a list of individual instruction (or byte) addresses
        based on the current metadata.
        """
        output = []
        for address, size in basic_blocks:
            instructions = self.get_instructions_slice(address, address+size)
            output.extend(instructions)
        return output

    def is_big(self):
        """
        Return a bool indicating whether we think the database is 'big'.
        """
        return len(self.functions) > 50000

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    def refresh(self, function_addresses=None, progress_callback=None):
        """
        Request an asynchronous refresh of the database metadata.

        TODO/FUTURE: we should make a synchronous refresh available
        """
        assert self._refresh_worker == None, 'Refresh already running'
        result_queue = Queue.Queue()

        #
        # reset the async abort/stop flag that can be used used to cancel the
        # ongoing refresh task
        #

        self._stop_threads = False

        #
        # kick off an asynchronous metadata collection task
        #

        self._refresh_worker = threading.Thread(
            target=self._async_refresh,
            args=(result_queue, function_addresses, progress_callback,)
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
        for function_metadata in self.functions.itervalues():
            instructions.extend(function_metadata.instructions)
        instructions = list(set(instructions))
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
        self._last_node = []
        self._name2func = { f.name: f.address for f in self.functions.itervalues() }
        self._node_addresses = sorted(self.nodes.keys())
        self._function_addresses = sorted(self.functions.keys())
        self._stale_lookup = False

    #--------------------------------------------------------------------------
    # Metadata Collection
    #--------------------------------------------------------------------------

    @not_mainthread
    def _async_refresh(self, result_queue, function_addresses, progress_callback):
        """
        The main routine for the asynchronous metadata refresh worker.

        TODO/FUTURE: this should be cleaned up / refactored
        """

        # pause our rename listening hooks (more performant collection)
        if self._rename_hooks:
            self._rename_hooks.unhook()

        #
        # if the caller provided no function addresses to target for refresh,
        # we will perform a complete metadata refresh of all database defined
        # functions. let's retrieve that list from the disassembler now...
        #

        if not function_addresses:
            function_addresses = disassembler.execute_read(
                disassembler.get_function_addresses
            )()

        # refresh database properties that we wish to cache
        self._async_refresh_properties()

        # refresh the core database metadata asynchronously
        completed = self._async_collect_metadata(
            function_addresses,
            progress_callback
        )

        # regenerate the instruction list from collected metadata
        self._refresh_instructions()

        # refresh the internal function/node fast lookup lists
        self._refresh_lookup()

        #
        # NOTE:
        #
        #   creating the hooks inline like this is less than ideal, but they
        #   they have been moved here (from the metadata constructor) to
        #   accomodate shortcomings of the Binary Ninja API.
        #
        # TODO/FUTURE/V35:
        #
        #   it would be nice to move these back to the constructor once the
        #   Binary Ninja API allows us to detect BV / sessions as they are
        #   created, and able to load plugins on such events.
        #

        #----------------------------------------------------------------------

        # create the disassembler hooks to listen for rename events
        if not self._rename_hooks:
            self._rename_hooks = disassembler.create_rename_hooks()
            self._rename_hooks.renamed = self._name_changed
            self._rename_hooks.metadata = weakref.proxy(self)

        #----------------------------------------------------------------------

        # reinstall the rename listener hooks now that the refresh is done
        self._rename_hooks.hook()

        # send the refresh result (good/bad) incase anyone is still listening
        if completed:
            self.cached = True
            result_queue.put(True)
        else:
            result_queue.put(False)

        # clean up our thread's reference as it is basically done/dead
        self._refresh_worker = None

        # thread exit...
        return

    @disassembler.execute_read
    def _async_refresh_properties(self):
        """
        Refresh a selection of interesting database properties.
        """
        self.filename = disassembler.get_root_filename()
        self.imagebase = disassembler.get_imagebase()

    @not_mainthread
    def _async_collect_metadata(self, function_addresses, progress_callback):
        """
        Collect metadata from the underlying database (interruptable).
        """
        CHUNK_SIZE = 150
        completed = 0

        start = time.time()
        #----------------------------------------------------------------------

        for addresses_chunk in chunks(function_addresses, CHUNK_SIZE):

            #
            # collect function metadata from the open database in groups of
            # CHUNK_SIZE. collect_function_metadata() takes a list of function
            # addresses and collects their metadata in a thread-safe manner
            #

            fresh_metadata = collect_function_metadata(addresses_chunk)

            # update our database metadata cache with the new function metadata
            self._update_functions(fresh_metadata)

            # report incremental progress to an optional progress_callback
            if progress_callback:
                completed += len(addresses_chunk)
                progress_callback(completed, len(function_addresses))

            # if the refresh was canceled, stop collecting metadata and bail
            if self._stop_threads:
                return False

            # sleep some so we don't choke the mainthread
            time.sleep(.0015)

        #----------------------------------------------------------------------
        end = time.time()
        logger.debug("Metadata collection took %s seconds" % (end - start))

        # refresh completed normally / was not interrupted
        return True

    def _update_functions(self, fresh_metadata):
        """
        Update stored function metadata with the given fresh metadata.

        Returns a map of {address: function metadata} that has been updated.
        """
        blank_function = FunctionMetadata(-1)

        #
        # the first step is to loop through the 'fresh' function metadata that
        # has been given to us, and identify what is truly new or different
        # from any existing metadata we hold.
        #

        for function_address, new_metadata in fresh_metadata.iteritems():

            # extract the 'old' metadata from the database metadata cache
            old_metadata = self.functions.get(function_address, blank_function)

            #
            # if the fresh metadata for this function is identical to the
            # existing metadata we have collected for it, there's nothing
            # else for us to do -- just ignore it.
            #

            if old_metadata == new_metadata:
                continue

            # delete nodes that explicitly no longer exist
            old = old_metadata.nodes.viewkeys() - new_metadata.nodes.viewkeys()
            for node_address in old:
                del self.nodes[node_address]

            #
            # the newly collected metadata for a given function is empty, this
            # indicates that the function has been deleted. we go ahead and
            # remove its old function metadata from the db metadata entirely
            #

            if new_metadata.empty:
                del self.functions[function_address]
                continue

            # add or overwrite the new/updated basic blocks
            self.nodes.update(new_metadata.nodes)

            # save the new/updated function
            self.functions[function_address] = new_metadata

        #
        # since the node / function metadata cache has probably changed, we
        # will need to refresh the internal fast lookup lists. this flag is
        # only really used for debugging, and will probably be removed
        # in the TODO/FUTURE collection refactor (v0.9?)
        #

        self._stale_lookup = True

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    @mainthread
    def _name_changed(self, address, new_name, local_name=None):
        """
        Handler for rename event in IDA.

        TODO/FUTURE: refactor this to not be so IDA-specific
        """

        # we should never care about local renames (eg, loc_40804b), ignore
        if local_name or new_name.startswith("loc_"):
            return 0

        # get the function that this address falls within
        function = self.get_function(address)

        # if the address does not fall within a function (might happen?), ignore
        if not function:
            return 0

        #
        # ensure the renamed address matches the function start before
        # renaming the function in our metadata cache.
        #
        # I am not sure when this would not be the case (globals? maybe)
        # but I'd rather not find out.
        #

        if address != function.address:
            return

        # if the name isn't actually changing (misfire?) nothing to do
        if new_name == function.name:
            return

        logger.debug("Name changing @ 0x%X" % address)
        logger.debug("  Old name: %s" % function.name)
        logger.debug("  New name: %s" % new_name)

        # rename the function, and notify metadata listeners
        #function.name = new_name
        function.refresh_name()
        self._notify_function_renamed()

        # necessary for IDP/IDB_Hooks
        return 0

    #--------------------------------------------------------------------------
    # Callbacks
    #--------------------------------------------------------------------------

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

#------------------------------------------------------------------------------
# Function Metadata
#------------------------------------------------------------------------------

class FunctionMetadata(object):
    """
    Function level metadata cache.
    """

    def __init__(self, address):

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
        if address != -1:
            self._build_metadata()

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def instructions(self):
        """
        Return the instruction addresses in this function.
        """
        return set([ea for node in self.nodes.itervalues() for ea in node.instructions])

    @property
    def empty(self):
        """
        Return a bool indicating whether the object is populated.
        """
        return len(self.nodes) == 0

    #--------------------------------------------------------------------------
    # Public
    #--------------------------------------------------------------------------

    @disassembler.execute_read
    def refresh_name(self):
        """
        Refresh the function name against the open database.
        """
        self.name = disassembler.get_function_name_at(self.address)

    #--------------------------------------------------------------------------
    # Metadata Population
    #--------------------------------------------------------------------------

    def _build_metadata(self):
        """
        Collect function metadata from the underlying database.
        """
        self.name = disassembler.get_function_name_at(self.address)
        self._refresh_nodes()
        self._finalize()

    def _refresh_nodes(self):
        """
        This will be replaced with a disassembler-specific function at runtime.

        NOTE: Read the 'MONKEY PATCHING' section at the end of this file.
        """
        raise RuntimeError("This function should have been monkey patched...")

    def _ida_refresh_nodes(self):
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

            # NOTE/COMPAT
            if disassembler.USING_IDA7API:
                node_start = node.start_ea
                node_end   = node.end_ea
            else:
                node_start = node.startEA
                node_end   = node.endEA

            #
            # the node current node appears to have a size of zero. This means
            # that another flowchart / function owns this node so we can just
            # ignore it...
            #

            if node_start == node_end:
                continue

            # create a new metadata object for this node
            node_metadata = NodeMetadata(node_start, node_end, node_id)

            #
            # establish a relationship between this node (basic block) and
            # this function metadata (its parent)
            #

            node_metadata.function = function_metadata
            function_metadata.nodes[node_start] = node_metadata

        # compute all of the edges between nodes in the current function
        for node_metadata in function_metadata.nodes.itervalues():
            edge_src = node_metadata.instructions[-1]
            for edge_dst in idautils.CodeRefsFrom(edge_src, True):
                if edge_dst in function_metadata.nodes:
                    function_metadata.edges[edge_src].append(edge_dst)

    def _binja_refresh_nodes(self):
        """
        Refresh function node metadata against an open Binary Ninja database.
        """
        function_metadata = self
        function_metadata.nodes = {}

        # get the function from the Binja database
        function = disassembler.bv.get_function_at(self.address)

        #
        # now we will walk the flowchart for this function, collecting
        # information on each of its nodes (basic blocks) and populating
        # the function & node metadata objects.
        #

        for node in function.basic_blocks:

            # create a new metadata object for this node
            node_metadata = NodeMetadata(node.start, node.end, node.index)

            #
            # establish a relationship between this node (basic block) and
            # this function metadata (its parent)
            #

            node_metadata.function = function_metadata
            function_metadata.nodes[node.start] = node_metadata

            #
            # enumerate the edges produced by this node (basic block) with a
            # destination that falls within this function.
            #

            edge_src = node_metadata.instructions[-1]
            for edge in node.outgoing_edges:
                function_metadata.edges[edge_src].append(edge.target.start)

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

        to_walk = set([self.address])
        while to_walk:

            # this is the address of the node we will 'walk' from
            node_address = to_walk.pop()
            confirmed_nodes.add(node_address)

            # now we loop through all edges that originate from this block
            current_src = self.nodes[node_address].instructions[-1]
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
        num_edges = sum(len(x) for x in confirmed_edges.itervalues())
        num_nodes = len(confirmed_nodes)
        return num_edges - num_nodes + 2

    def _finalize(self):
        """
        Finalize function metadata for use.
        """
        self.size = sum(node.size for node in self.nodes.itervalues())
        self.node_count = len(self.nodes)
        self.edge_count = len(self.edges)
        self.instruction_count = sum(node.instruction_count for node in self.nodes.itervalues())
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
        result &= self.nodes.viewkeys() == other.nodes.viewkeys()
        return result

#------------------------------------------------------------------------------
# Node Metadata
#------------------------------------------------------------------------------

class NodeMetadata(object):
    """
    Node (basic block) level metadata cache.
    """

    def __init__(self, start_ea, end_ea, node_id=None):

        # node metadata
        self.size = end_ea - start_ea
        self.address = start_ea
        self.instruction_count = 0

        # flowchart node_id
        self.id = node_id

        # parent function_metadata
        self.function = None

        # instruction addresses
        self.instructions = []

        #----------------------------------------------------------------------

        # collect metadata from the underlying database
        self._build_metadata()

    #--------------------------------------------------------------------------
    # Metadata Population
    #--------------------------------------------------------------------------

    def _build_metadata(self):
        """
        This will be replaced with a disassembler-specific function at runtime.

        NOTE: Read the 'MONKEY PATCHING' section at the end of this file.
        """
        raise RuntimeError("This function should have been monkey patched...")

    def _ida_build_metadata(self):
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
            self.instructions.append(current_address)
            current_address += instruction_size

        # save the number of instructions in this block
        self.instruction_count = len(self.instructions)

    def _binja_build_metadata(self):
        """
        Collect node metadata from the underlying database.
        """
        bv = disassembler.bv
        current_address = self.address
        node_end = self.address + self.size

        #
        # Note that we 'iterate over' the instructions using their byte length
        # because it is far more performant than Binary Ninja's instruction
        # generators which also produce instruction text, tokens etc...
        #

        while current_address < node_end:
            self.instructions.append(current_address)
            current_address += bv.get_instruction_length(current_address)

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
        output += " Function: %s\n" % self.function
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
        result &= self.function == other.function
        result &= self.id == other.id
        return result

#------------------------------------------------------------------------------
# Async Metadata Helpers
#------------------------------------------------------------------------------

@disassembler.execute_read
def collect_function_metadata(function_addresses):
    """
    Collect function metadata for a list of addresses.
    """
    return { ea: FunctionMetadata(ea) for ea in function_addresses }

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
    NodeMetadata._build_metadata = NodeMetadata._ida_build_metadata

elif disassembler.NAME == "BINJA":
    import binaryninja
    FunctionMetadata._refresh_nodes = FunctionMetadata._binja_refresh_nodes
    NodeMetadata._build_metadata = NodeMetadata._binja_build_metadata

else:
    raise NotImplementedError("DISASSEMBLER-SPECIFIC SHIM MISSING")
