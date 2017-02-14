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

    def __init__(self, address, name=None, nodes_total=0):
        self.name          = name
        self.address       = address
        self.nodes_total   = nodes_total
        self.nodes_tainted = set()       # TODO: create a basic block coverage item

        # automatically fill the fields we were not passed
        self._self_populate()

    @property
    def percent_node(self):
        """
        Return the coverage percent by basic block (node) percentage.
        """
        try:
            return (float(len(self.nodes_tainted)) / self.nodes_total)
        except ZeroDivisionError:
            return 0

    def _self_populate(self):
        """
        Populate the function fields against the open IDB.

        TODO/NOTE:

          The purpose of this function is to self populate the fields that
          were not given to us upon initialization. The concern is that these
          actions (eg, querying the database) are considered expensive and
          may add up when dealing with larger data sets.

          Ideally, most of this will have been passed in when constructed,
          re-using the existing knowledge rather than reading from the IDB.

          Right now, the gains are probably negligible.

        """
        function, flowchart = None, None

        # get the function name from the database
        if not self.name:
            self.name = idaapi.get_func_name2(self.address)

        # get the function name from the database
        if not self.nodes_total:
            function  = idaapi.get_func(self.address)
            flowchart = idaapi.FlowChart(function)
            self.nodes_total = flowchart.size

    #----------------------------------------------------------------------
    # Controls
    #----------------------------------------------------------------------

    def taint_node(self, node_id):
        """
        Add the given node ID to the set of tainted nodes.
        """
        self.nodes_tainted.add(node_id)

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
        function  = idaapi.get_func(address)
        flowchart = idaapi.FlowChart(function)

        # find the basic block (node) that our coverage block must start in
        for bb in flowchart:

            # the coverage block (address) starts in this basic block
            if bb.startEA <= address < bb.endEA:

                #
                # first, we need to save this basic block id as we know it
                # definitely is hit by some part of our coverage block
                #

                # add the bb (node) id to an existing function coverage object
                function_map[function.startEA].taint_node(bb.id)

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
                    fragment_size   = end_address - bb.endEA
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
