import logging
import collections

import idaapi
import idautils

logger = logging.getLogger("Lighthouse.Coverage")

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
        self.functions = init_function_converage()
        self.orphans = build_function_coverage(self.functions, self.coverage_data)

#------------------------------------------------------------------------------
# Function Level Coverage
#------------------------------------------------------------------------------

class FunctionCoverage(object):
    """
    Manages coverage data at the function level.

    This wraps basic function metadata (address, name, # of nodes, etc)
    and provides access/metrics to coverage data at a function level.
    """

    def __init__(self, address, name=None):

        # function metadata
        self.name          = name
        self.address       = address
        self.size          = 0

        # node metadata
        self.nodes         = {}
        self.executed_nodes = set()

        # counters
        self.node_count = 0
        self.insn_count = 0

        # automatically fill the fields we were not passed
        self._self_populate()

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

    def _self_populate(self):
        """
        Populate the function fields against the open IDB.
        """

        # get the function name from the database
        if not self.name:
            self.name = idaapi.get_func_name2(self.address)

        # get the function nodes from the database
        if not self.node_count:
            self._self_populate_nodes()

    def _self_populate_nodes(self):
        """
        Populate the function nodes against the open IDB.
        """
        assert self.size == 0

        function  = idaapi.get_func(self.address)
        flowchart = idaapi.FlowChart(function)

        # build a map of NodeEA --> NodeCoverage
        for node in flowchart:
            new_node = NodeCoverage(node)
            self.size += new_node.size
            self.nodes[node.startEA] = NodeCoverage(node)

        # bake the size in so we don't have to use len() on nodes constantly
        assert len(self.nodes) == flowchart.size
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
       functions[function_address] = FunctionCoverage(function_address)
    return functions

def build_function_coverage(function_map, coverage_blocks):
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
    #function_map = {} # functionEA -> FunctionCoverage()

    # orphans is a list of tuples (offset, size) of coverage that could
    # not be mapped into any defined basic blocks.
    orphans  = [] # [(offset, size), ...]

    # NOTE/PERF: we're cloning a potentially large list here
    blocks = collections.deque(coverage_blocks)
    while blocks:

        # pop off the next coverage block, and compute its rebased address
        address, size = blocks.popleft()

        # TODO/NOTE/PERF: consider caching these lookups below
        # find the function & graph the coverage block *should* fall in
        try:
            function  = idaapi.get_func(address)
            flowchart = idaapi.FlowChart(function)

        # coverage is not in a mapped function
        except Exception as e:
            flowchart = []

        # find the basic block (node) that our coverage block must start in
        for bb in flowchart:

            # the coverage block (address) starts in this basic block
            if bb.startEA <= address < bb.endEA:

                #
                # first, we need to taint this basic block address as we know
                # it definitely is hit by some part of our coverage block
                #

                function_map[function.startEA].mark_node(bb.startEA)

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

    # return only the orphans, as the function_map was updated in place
    return orphans
