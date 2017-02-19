import logging
import collections

import idaapi
import idautils

logger = logging.getLogger("Lighthouse.Coverage")

class FlowChartCache(object):
    """
    TODO
    """
    def __init__(self, capacity):
        #self.cache = collections.OrderedDict()
        self.cache = collections.deque([], capacity)
        self.cache_map = collections.OrderedDict()

    def get(self, address):
        """
        Cached lookup of the flowchart for a given address.

        On cache-miss, a new flowchart is generated.
        """

        # cache hit
        for cache_entry in self.cache:
            bounds = cache_entry[0]._q.bounds
            if bounds.startEA <= address < bounds.endEA:
                #logger.debug("0x%08X: cache hit!" % address)
                return cache_entry

        #
        # flow chart is NOT in the cache...
        #

        #logger.debug("0x%08X: cache miss!" % address)

        # create a new flowchart corresponding to the address
        function  = idaapi.get_func(address)
        flowchart = idaapi.FlowChart(function) # NOTE: throws if function is invalid

        # cache the newly created flowchart
        cache_entry = (flowchart, 0)
        self.set(cache_entry)

        # return the created flowchart entry
        return cache_entry

    def set(self, cache_entry):
        """
        Update the cache with the given entry.
        """
        function_address = cache_entry[0]._q.bounds.startEA

        # evict an old entry if it exists
        for i in xrange(len(self.cache)):
            if self.cache[i][0]._q.bounds.startEA == function_address:
                del self.cache[i]
                break

        # put this new entry at the front of the list
        self.cache.appendleft(cache_entry)

#------------------------------------------------------------------------------
# Database Level Coverage
#------------------------------------------------------------------------------

class DatabaseCoverage(object):
    """
    Manages coverage data and metrics for the whole database.

    TODO/NOTE:

      In the long run, I imagine this class will grow to become
      the hub for all coverage data. By the time the coverage reaches
      this hub, it should be in a generic (offset, size) block format.

      This hub will be the data source should a user wish to flip
      between any loaded coverage, or even view metrics on a union of
      the loaded overages.

      As the class sits now, it is minimal and caters to only a single
      source of coverage data.

    """

    def __init__(self):
        self.coverage_data = None
        self.functions = {}
        self.orphans = []

    def add_coverage(self, base, coverage_data):
        """
        Enlighten the database to new coverage data.
        """
        self.coverage_data = bake_coverage_addresses(base, coverage_data)

        # build function level coverage
        #self.functions = init_function_converage()
        self.build_function_coverage(self.coverage_data)

    #--------------------------------------------------------------------------
    # Internal routines
    #--------------------------------------------------------------------------


    def build_function_coverage(self, coverage_blocks):
        """
        Map block based coverage data to database defined basic blocks (nodes).

        -----------------------------------------------------------------------

        NOTE:

        I don't like writing overly large / complex functions. But this
        will be an important high compute + IDB access point for larger
        data sets,

        I put some effort into reducing database access, excessive searches,
        iterations, etc. I am concerned about performance overhead that may
        come with trying to break this out into multiple functions, but I
        encourage you to try :-)

        -----------------------------------------------------------------------

        Input:
        - function_map:
            a clean map of functionEA --> FunctionCoverage()
        - coverage_blocks:
            a list of tuples in (offset, size) format that define coverage

        Output:
        - function_map:
            udpated as a parameter
        - orphans:
            returned, read comments below for more details

        """

        #
        # The purpose of this mega while loop is to process the raw block
        # based coverage data and build a comprehensive mapping of nodes
        # throughout the database that are tainted by it.
        #
        # This loop will produce two outputs:
        #

        # function_map is keyed with a function address and holds function coverage
        function_map = {} # functionEA -> FunctionCoverage()

        # orphans is a list of tuples (offset, size) of coverage that could
        # not be mapped into any defined basic blocks.
        orphans  = [] # [(offset, size), ...]

        # TODO
        FLOWCHART_CACHE_SIZE = 6
        flowchart_cache = FlowChartCache(FLOWCHART_CACHE_SIZE)

        # NOTE/PERF: we're cloning a potentially large list here
        blocks = collections.deque(coverage_blocks)
        while blocks:

            # pop off the next coverage block
            address, size = blocks.popleft()

            # retrieve the flowchart for this address
            try:
                flowchart, cached_base = flowchart_cache.get(address)

            # failed to locate flowchart for this address. the address likely
            # does not fall inside of a defined function
            except Exception as e:
                #logger.debug("Could not find flowchart for 0x%08x" % address)
                orphans.append((address, size))
                continue

            # alias the function's address from the flowchart for convenience
            function_address = flowchart._q.bounds.startEA

            #
            # At this point, we have located the flowchart corresponding to
            # this address. We are now ready to identify which node our
            # current coverage block (address, size) starts in.
            #

            #
            # walk through every node (basic block) in the flowchart until a
            # a node corresponding with our coverage block is found
            #

            flowchart_size = flowchart.size
            #logger.debug("[0x%08x] Flowchart 0x%08x, size %u" % (address, flowchart._q.bounds.startEA, flowchart_size))
            for count in xrange(flowchart_size):

                # get the last basic block we started on
                index = (cached_base + count) % flowchart_size
                bb = flowchart[index]
                #logger.debug("[0x%08x] checking index %u" % (address, index))
                #logger.debug("  - 0x%08x <= 0x%08x < 0x%08x : %r" % (bb.startEA, address, bb.endEA, (bb.startEA <= address < bb.endEA)))

                # the coverage block (address) starts in this node
                if bb.startEA <= address < bb.endEA:

                    #
                    # first, retrieve the coverage data item for the function
                    # corresponding with this flowchart.
                    #

                    try:
                        function_coverage = function_map[function_address]

                    #
                    # looks like this is the first time we have identiied
                    # coverage for this function. creaate a coverage data item
                    # for the function now and use that
                    #

                    except KeyError as e:
                        function_coverage = FunctionCoverage(flowchart)
                        function_map[function_address] = function_coverage

                    #
                    # now we taint the basic block that we hit
                    #

                    function_map[function_address].mark_node(bb.startEA)

                    #
                    # depending on coverage & bb quality, we also check for
                    # the possibility of a fragment due to the coverage block
                    # spilling into the next basic block.
                    #

                    # does the coverage block spill past this basic block?
                    end_address = address + size
                    if end_address > bb.endEA:

                        # yes, compute the fragment size and prepend the work
                        # to be consumed later (next iteration, technically)
                        fragment_address = bb.endEA
                        fragment_size    = end_address - bb.endEA
                        blocks.appendleft((fragment_address, fragment_size))

                    # update the flowchart cache
                    flowchart_cache.set((flowchart, bb.id))

                    # all done, break from the bb for loop
                    break

                # end of if statement

            # end of for loop

            #
            # We made it through the entire flowchart for this function without
            # finding an appropriate basic block (node) for the coverage data.
            # this is strange, but whatever... just log the fragment as an
            # orphan for later investigation.
            #

            else:
                orphans.append((address, size))

        # end of while loop

        # add blank entries to the function map
        # NOTE: no need to use a cache here, linear sweep
        for function_address in idautils.Functions():
            if function_address not in function_map:
                function  = idaapi.get_func(function_address)
                flowchart = idaapi.FlowChart(function)
                function_map[function_address] = FunctionCoverage(flowchart)

        # TODO
        self.orphans = orphans
        self.functions = function_map

#------------------------------------------------------------------------------
# Function Level Coverage
#------------------------------------------------------------------------------

class FunctionCoverage(object):
    """
    Manages coverage data at the function level.

    This wraps basic function metadata (address, name, # of nodes, etc)
    and provides access/metrics to coverage data at a function level.
    """

    def __init__(self, flowchart, name=None):

        # function metadata
        self.name          = name
        self.address       = flowchart._q.bounds.startEA
        self.size          = 0

        # node metadata
        self.nodes         = {}
        self.executed_nodes = set()

        # counters
        self.node_count = 0
        self.insn_count = 0

        # automatically fill the fields we were not passed
        self._self_populate(flowchart)

    @property
    def instructions(self):
        """
        The number of instructions in this function.
        """
        return sum(node.instructions for node in self.nodes.itervalues())

    @property
    def executed_instructions(self):
        """
        The number of executed instructions in this function.
        """
        return sum(node.instructions for node in self.executed_nodes)

    @property
    def percent_instruction(self):
        """
        The function coverage percentage by instruction execution.
        """
        try:
            return (float(self.executed_instructions) / self.instructions)
        except ZeroDivisionError:
            return 0

    @property
    def percent_node(self):
        """
        The function coverage percentage by node (basic block) execution.
        """
        try:
            return (float(len(self.executed_nodes)) / self.node_count)
        except ZeroDivisionError:
            return 0

    #----------------------------------------------------------------------
    # Information Population
    #----------------------------------------------------------------------

    def _self_populate(self, flowchart):
        """
        Populate the function fields against the open IDB.
        """

        # get the function name from the database
        if not self.name:
            self.name = idaapi.get_func_name2(self.address)

        # get the function's nodes from the database
        if not self.node_count:
            self._self_populate_nodes(flowchart)

    def _self_populate_nodes(self, flowchart):
        """
        Populate the function nodes against the open IDB.
        """
        assert self.size == 0

        #
        # iterate through every node (basic block) in the flowchart for a given
        # function so that we may initialize a NodeEA --> NodeCoverage map
        #

        for node in flowchart:

            # first, create a new node coverage item for this node
            new_node = NodeCoverage(node)

            # add the node's byte size to our computed function size
            self.size += new_node.size

            # save the node coverage item into our function's node map
            self.nodes[node.startEA] = new_node

        assert len(self.nodes) == flowchart.size

        # bake the total node count in so we don't re-compute it repeatedly
        self.node_count = flowchart.size

    #----------------------------------------------------------------------
    # Controls
    #----------------------------------------------------------------------

    def mark_node(self, start_address):
        """
        Add the given node ID to the set of tainted nodes.
        """
        self.executed_nodes.add(self.nodes[start_address])

#------------------------------------------------------------------------------
# Node Level Coverage
#------------------------------------------------------------------------------

class NodeCoverage(object):
    """
    Manages coverage data at the node (basic block) level.

    TODO:
    This wraps basic function metadata (address, name, # of nodes, etc)
    and provides access/metrics to coverage data at a function level.
    """

    def __init__(self, node):
        self.address       = node.startEA
        self.size          = node.endEA - node.startEA
        self.id            = node.id
        self.instructions  = 0

        # loop through the entire region and count the instructions
        # in this node
        current_address = self.address
        while node.endEA > current_address:
            self.instructions += 1
            current_address = idaapi.next_not_tail(current_address)

#------------------------------------------------------------------------------
# Coverage Helpers
#------------------------------------------------------------------------------

def bake_coverage_addresses(base, coverage_blocks):
    """
    Bake relative coverage offsets into absolute addresses, in-place.
    """
    for i in xrange(len(coverage_blocks)):
        offset, size = coverage_blocks[i]
        coverage_blocks[i] = (base + offset, size)
    return coverage_blocks

def init_function_converage():
    """
    Build a clean function map ready to populate with future coverage.
    """
    functions = {}
    for function_address in idautils.Functions():
        function  = idaapi.get_func(function_address)
        flowchart = idaapi.FlowChart(function)
        functions[function_address] = FunctionCoverage(flowchart)
    return functions

