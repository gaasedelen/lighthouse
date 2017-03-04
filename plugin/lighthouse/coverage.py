import bisect
import logging
import collections

import idaapi
import idautils

from lighthouse.util import *
from lighthouse.util import compute_color_on_gradiant, FlowChartCache
from lighthouse.painting import *

logger = logging.getLogger("Lighthouse.Coverage")

#------------------------------------------------------------------------------
# Database Level Coverage
#------------------------------------------------------------------------------

class CoverageDirector(object):
    """

    TODO/NOTE:

      In the long run, I imagine this class will grow to become
      the hub for all coverage data. By the time the coverage reaches
      this hub, it should be in a generic (offset, size) block format.

      This hub will be the data source should a user wish to flip
      between any loaded coverage, or even view metrics on a union of
      the loaded overages.

      As the class sits now, it is minimal and caters to only a single
      source of coverage data.

      # - Databbase/ function / node metadata can be a shared resource
      # - Only coverage changes

    """

    def __init__(self, palette):
        self._database_metadata = DatabaseMetadata()
        self._database_coverage = {}
        self._palette = palette
        self._composite_coverage = None
        self.refresh()

    @property
    def metadata(self):
        return self._database_metadata

    @property
    def coverage(self):
        return self._composite_coverage

    @property
    def loaded_filenames(self):
        return self._database_coverage.iterkeys()

    def refresh(self):
        """
        Complete refresh of coverage mapping to the active database.
        """
        logger.debug("Refreshing Coverage Director")

        # (re)build our knowledge of the underlying database
        self._refresh_database_info()

        # (re)map each set of coverage data to the database
        self._refresh_database_coverage()

    def _refresh_database_info(self):
        """
        Refresh the database info cache utilized by the director.
        """
        logger.debug("Refreshing database metadata")

        self._database_metadata.refresh()
        # TODO: return metadata delta

    def _refresh_database_coverage(self):
        """
        Refresh the database coverage mappings managed by the director.
        """
        logger.debug("Refreshing coverage mappings")
        for name, coverage in self._database_coverage:
            logger.debug(" - %s" % name)
            coverage.refresh(self._database_metadata)

    def select_coverage(self, coverage_name):
        """
        TODO
        """
        self._composite_coverage = self._database_coverage[coverage_name]
        self.paint_coverage()

    #@profile
    def add_coverage(self, name, base, coverage_data):
        """
        Add new coverage data to the director.
        """
        logger.debug("Adding coverage %s" % name)

        # initialize a new database coverage for this 'file' / data
        new_coverage = DatabaseCoverage(base, coverage_data, self._palette)

        # map the coverage data using the database metadata
        new_coverage.refresh(self._database_metadata)

        # coverage creation & mapping complete, looks like we're good. add it
        # to the director's coverage table and surface it for use
        self._database_coverage[name] = new_coverage

    def paint_coverage(self):
        """
        TODO: do we really want this in here?
        """

        #
        # depending on if IDA is using a dark or light theme, we paint
        # coverage with a color that will hopefully keep things readable.
        # determine whether to use a 'dark' or 'light' paint
        #

        bg_color = get_disas_bg_color()
        if bg_color.lightness() > 255.0/2:
            color = self._palette.paint_light
        else:
            color = self._palette.paint_dark

        # color the database based on coverage
        paint_coverage(self.metadata, self.coverage, color)

#------------------------------------------------------------------------------
# Database Level Coverage
#------------------------------------------------------------------------------

class DatabaseMetadata(object):
    """
    Fast access database level metadata.
    """

    def __init__(self):

        # database defined nodes (basic blocks)
        self.nodes = {}
        self._node_addresses = []

        # database defined functions
        self.functions = {}
        self._function_addresses = []

        # database defined segments
        #self.segments = {}
        #self._segment_addresses = {}

    def get_node(self, address):
        """
        Get the node (basic block) for a given address.
        """

        # TODO: consider using sortedcontainers
        #found = sorted_dict.iloc[(sorted_dict.bisect_left(address) - 1)]

        # find the index of the closest address (rounding down) in the node list
        node_index = bisect.bisect_right(self._node_addresses, address) - 1

        # retrieve the actual node (basic block) from the node map
        try:
            node = self.nodes[self._node_addresses[node_index]]
            if node.address <= address < node.address + node.size:
                return node
        except KeyError:
            pass

        raise ValueError("Given address does not fall within a known node")

    #----------------------------------------------------------------------
    # Metadata Population
    #----------------------------------------------------------------------

    def refresh(self):
        """
        Refresh database metadata.
        """
        self._build_metadata()

    def _build_metadata(self):
        """
        Collect metadata from the underlying database.
        """

        # for now....
        assert not self.nodes
        assert not self.functions
        assert not self._node_addresses
        assert not self._function_addresses

        # loop through every defined function in the database
        for function_address in idautils.Functions():

            # get the function & its associated flowchart
            function  = idaapi.get_func(function_address)
            flowchart = idaapi.qflow_chart_t("", function, idaapi.BADADDR, idaapi.BADADDR, 0)

            # initialize the metadata object for this function
            function_metadata = FunctionMetadata(function_address)

            #
            # now we will walk the flowchart for this function, collecting
            # information on each of its nodes (basic blocks) and populating
            # the function & node metadata objects.
            #

            for node_id in xrange(flowchart.size()):
                node_address = flowchart[node_id].startEA

                #
                # attempt to select the node via address from our current
                # database-wide node list (should the node already exist)
                #   eg: a node may be shared between multiple functions
                #

                try:
                    node_metadata = self.nodes[node_address]

                # the node metadata does NOT exist yet, so create it now
                except KeyError as e:
                    node_metadata = NodeMetadata(flowchart[node_id])
                    self.nodes[node_address] = node_metadata

                #
                # establish a relationship between this node (basic block) and
                # this function (as one of its owners)
                #

                function_metadata.nodes[node_address]     = node_metadata
                node_metadata.functions[function_address] = function_metadata

                #
                # a node's id will be unique per flowchart (function). we need
                # these id's cached such that we can quickly paint nodes.
                #
                # save the node's id as it exists in *this* function into a
                # map, keyed by the function address
                #

                node_metadata.ids[function_address] = node_id

            # 'bake' elements of the function metadata for faster future use
            function_metadata.finalize()

            # add the function metadata to our database-wide function list
            self.functions[function_address] = function_metadata

        #
        # now that we have collected all the node & function metadata available
        # to us at this time, we create sorted lists of just their addresses so
        # we can perform fast fuzzy lookup (eg, bisect) by address later on.
        #
        # fuzzy lookup in this context is the ability to quickly identify
        # the node or function that a given address may fall within. Since any
        # given address is unlikely to fall on a node/function boundary, one
        # will not be able to index directly into the nodes of functions dict
        # we have built.
        #
        # Instead, one will want to locate the closest object prior to a given
        # address via these address lists, and then extract the object from its
        # respective dict.
        #

        self._node_addresses = sorted(self.nodes.keys())
        self._function_addresses = sorted(self.functions.keys())

        # done
        #print "Done building metadata"
        #print " %u nodes" % len(self._node_addresses)
        #print " %u functions" % len(self._function_addresses)

class DatabaseCoverage(object):
    """
    Database level coverage map.
    """

    def __init__(self, base, coverage_data, palette):
        self._coverage_data = bake_coverage_addresses(base, coverage_data)
        self._palette = palette

        # coverage objects
        self.nodes     = {}
        self.functions = {}

        # orphan coverage blocks
        self.orphans = []

    #----------------------------------------------------------------------
    # Metadata Population
    #----------------------------------------------------------------------

    def refresh(self, db_metadata):
        """
        Refresh the mapping of our coverage data to the database.
        """
        self._map_coverage(db_metadata)
        self._finalize(db_metadata)

    def _finalize(self, db_metadata):
        """
        Finalize coverage data.
        """

        # finalize node level coverage data
        for node_coverage in self.nodes.itervalues():
            node_coverage.finalize(db_metadata.nodes[node_coverage.address], self._palette)

        # finalize function level coverage data
        for function_coverage in self.functions.itervalues():
            function_coverage.finalize(db_metadata.functions[function_coverage.address], self._palette)

    #----------------------------------------------------------------------
    # Coverage Mapping
    #----------------------------------------------------------------------

    def _map_coverage(self, db_metadata):
        """
        Map loaded coverage data to the given database metadata.
        """

        # clear our existing mapping of coverage objects
        self.nodes     = {}
        self.functions = {}
        self.orphans   = []

        # TODO
        self._map_nodes(db_metadata)

        # TODO
        self._map_functions(db_metadata)

        #
        # We are done processing the coverage data given to us. Now we
        # enumerate and initialize all the functions that had no coverage.
        #

        ## NOTE: linear sweep, no reason to use the flowcache here
        #for function_address in idautils.Functions():
        #    if function_address not in function_map:
        #        function  = idaapi.get_func(function_address)
        #        flowchart = idaapi.qflow_chart_t("", function, idaapi.BADADDR, idaapi.BADADDR, 0)
        #        function_map[function_address] = FunctionCoverage(flowchart)

        ## done, return results
        #return (function_map, orphans)

    def _map_nodes(self, db_metadata):
        """
        Map loaded coverage data to database defined nodes (basic blocks).
        """
        assert self.nodes == {}

        #
        # The purpose of this mega while loop is to process the raw block
        # based coverage data wrapped by this DatabaseCoverage object and
        # build a comprehensive mapping of this data to elements of the
        # database as defined by the given database metadata
        #

        blocks = collections.deque(self._coverage_data)
        while blocks:

            # pop off the next work item, eg a coverage block to map to the db
            address, size = blocks.popleft()

            # why would you have a zero size block??
            assert size, "Size of coverage block must be non-zero"

            # get the node (basic block) that contains this address
            try:
                node_metadata = db_metadata.get_node(address)

            #
            # failed to locate node (basic block) for this address. this
            # address must not fall inside of a defined function... mark the
            # block as an orphan and move on.
            #
            #  NOTE/TODO:
            #    address --> address+size may contain the start of a node, so
            #    we might actually skip some stuff here...
            #

            except ValueError:
                self.orphans.append((address, size))
                continue

            #
            # retrieve the coverage object for this node address
            #

            try:
                node_coverage = self.nodes[node_metadata.address]

            #
            # failed to locate a node coverage object, looks like this is
            # the first time we have identiied coverage for this node.
            # creaate a coverage node object and use it now.
            #

            except KeyError as e:
                node_coverage = NodeCoverage(node_metadata)
                self.nodes[node_metadata.address] = node_coverage

            #
            # depending on coverage & bb quality, we also check for
            # the possibility of a fragment due to the coverage block
            # spilling into the next basic block.
            #

            # does the coverage block spill past this basic block?
            coverage_end = address + size
            node_end     = node_metadata.address + node_metadata.size
            if node_end < coverage_end:

                # yes, compute the fragment size and prepend the work
                # to be consumed later (next iteration, technically)
                fragment_address = node_end
                fragment_size    = coverage_end - node_end
                blocks.appendleft((fragment_address, fragment_size))

        # end of blocks loop

        # done
        return

    def _map_functions(self, db_metadata):
        """
        Map loaded coverage data to database defined nodes (basic blocks).
        """
        assert self.functions == {}

        #
        # TODO: comment cleanup
        #

        for node_coverage in self.nodes.itervalues():
            functions = db_metadata.nodes[node_coverage.address].functions

            # loop through every function that references this node so that we
            for function_metadata in functions.itervalues():

                #
                # retrieve the coverage object for this function address
                #

                try:
                    function_coverage = self.functions[function_metadata.address]

                #
                # failed to locate a function coverage object, looks like this
                # is the first time we have identiied coverage for this
                # function. creaate a coverage function object and use it now.
                #

                except KeyError as e:
                    function_coverage = FunctionCoverage(function_metadata)
                    self.functions[function_metadata.address] = function_coverage

                #
                # now we taint the basic block that we hit
                #

                function_coverage.mark_node(node_coverage)

                # TODO: uh, anything else?

            # end of functions loop

        # end of nodes loop

        # done
        return

#------------------------------------------------------------------------------
# Function Level Coverage
#------------------------------------------------------------------------------

class FunctionMetadata(object):
    """
    Fast access function level metadata.
    """

    def __init__(self, address):

        # function metadata
        self.address = address
        self.name    = None

        # node metadata
        self.nodes = {}

        # baked metrics
        self.fast_size = 0
        self.fast_node_count = 0
        self.fast_instruction_count = 0

        # automatically fill the fields we were not passed
        self.refresh()

    @property
    def instruction_count(self):
        """
        The number of instructions in this function.
        """
        return sum(node.instruction_count for node in self.nodes.itervalues())

    @property
    def node_count(self):
        """
        The number of nodes in this function.
        """
        return len(self.nodes)

    @property
    def size(self):
        """
        The size of the function in bytes (by node contents).
        """
        return sum(node.size for node in self.nodes.itervalues())

    def finalize(self):
        """
        Bake function metadata for faster access.
        """
        self.fast_size = self.size
        self.fast_node_count = self.node_count
        self.fast_instruction_count = self.instruction_count
        self.name = idaapi.get_func_name2(self.address) # TODO: this seems weird to have here

    #----------------------------------------------------------------------
    # Metadata Population
    #----------------------------------------------------------------------

    def refresh(self):
        """
        Refresh the function fields against the open IDB.
        """
        # TODO

        # get function & flowchart object from IDB
        #function  = idaapi.get_func(self.address)
        #flowchart = idaapi.qflow_chart_t("", function, idaapi.BADADDR, idaapi.BADADDR, 0)

        # get the function name from the database
        #self._refresh_name()

        # get the function's nodes from the database
        #self._refresh_nodes(flowchart)
        pass

    def _refresh_name(self):
        """
        Refresh the function name against the open IDB.
        """
        self.name = idaapi.get_func_name2(self.address)

    def _refresh_nodes(self, flowchart):
        """
        Refresh the function nodes against the open IDB.
        """

        # dispose of stale information
        self.nodes = {}
        #self.instruction_count = 0 # TODO: profile

        #
        # iterate through every node (basic block) in the flowchart for a given
        # function so that we may build node level metadata
        #

        for node_id in xrange(flowchart.size()):

            # first, create a new node coverage item for this node
            new_node = NodeMetadata(flowchart[node_id], node_id)

            # TODO: profile
            # add the node's byte size to our computed function size
            #self.size += new_node.size
            #self.instruction_count += new_node.instruction_count

            # save the node coverage item into our function's node map
            self.nodes[new_node.address] = new_node

        # TODO: profile
        # bake function level metrics so they don't get re-computed every use
        self.node_count = flowchart.size()
        self.size = sum(node.size for node in self.nodes)
        self.instruction_count = sum(node.instruction_count for node in self.nodes)

    #--------------------------------------------------------------------------
    # Misc
    #--------------------------------------------------------------------------

    def name_changed(self, new_name):
        """
        Handler for rename event in IDA.
        """
        self.name = new_name

#------------------------------------------------------------------------------
# Metadata Population
#------------------------------------------------------------------------------

class FunctionCoverage(object):
    """
    Function level coverage map.
    """

    def __init__(self, function_metadata):
        self.address = function_metadata.address

        # addresses of nodes executed
        self.executed_nodes = {} # TODO: Weakref?

        # baked colors
        self.coverage_color  = 0
        self.profiling_color = 0

        # compute the # of instructions executed by this function's coverage
        self.instruction_percent = 0.0
        self.instructions_executed = 0
        self.node_percent = 0.0
        self.nodes_executed = 0
        self.coverage_color = QtGui.QColor(30, 30, 30)
        self.profiling_color = 0

        # TODO ?
        #  - was the starting block hit?
        #  - instruction count
        #  - byte size

    #@property
    #def instructions_executed(self):
    #    """
    #    The number of executed instructions in this function.
    #    """
    #    return sum(node.instruction_count for node in self.exec_nodes)

    #@property
    #def percent_instruction(self):
    #    """
    #    The function coverage percentage by instruction execution.
    #    """
    #    try:
    #        return (float(self.executed_instruction_count) / self.instructions)
    #    except ZeroDivisionError:
    #        return 0

    #@property
    #def percent_node(self):
    #    """
    #    The function coverage percentage by node (basic block) execution.
    #    """
    #    try:
    #        return (float(len(self.exec_nodes)) / self.node_count)
    #    except ZeroDivisionError:
    #        return 0

    #----------------------------------------------------------------------
    # Controls
    #----------------------------------------------------------------------

    def mark_node(self, node_coverage):
        """
        Mark the given node address as executed.
        """
        self.executed_nodes[node_coverage.address] = node_coverage

    def finalize(self, function_metadata, palette):
        """
        Finalize the coverage metrics for faster access.
        """

        # compute the # of instructions executed by this function's coverage
        self.instructions_executed = 0
        for node_address in self.executed_nodes.iterkeys():
            self.instructions_executed += function_metadata.nodes[node_address].instruction_count

        # TODO: profile against fast_instruction_count
        # compute the % of instructions executed
        self.instruction_percent = float(self.instructions_executed) / function_metadata.instruction_count

        # TODO: profile, is this really gonna be faster in the long term...?
        # compute the number of nodes executed
        self.nodes_executed = len(self.executed_nodes)

        # TODO: profile against fast_node_count
        # compute the % of nodes executed
        self.node_percent = float(self.nodes_executed) / function_metadata.node_count

        # bake colors
        self.coverage_color = compute_color_on_gradiant(
            self.instruction_percent,
            palette.coverage_bad,
            palette.coverage_good
        )

        # TODO
        #self.profiling_color = compute_color_on_gradiant(
        #    self.insn_percent,
        #    palette.profiling_cold,
        #    palette.profiling_hot
        #)

#------------------------------------------------------------------------------
# Node Level Coverage
#------------------------------------------------------------------------------

class NodeMetadata(object):
    """
    Fast access node metadata container.
    """

    def __init__(self, node):

        # node metadata
        self.size = node.endEA - node.startEA
        self.address = node.startEA
        self.instruction_count = 0

        # maps function_address --> node_id
        self.ids = {}

        # maps function_address --> function_metadata
        self.functions = {}

        # populate the node
        self.refresh()

    def refresh(self):
        """
        TODO
        """

        # loop through the node's entire range and count its instructions
        current_address = self.address
        while current_address < self.address + self.size:
            self.instruction_count += 1
            current_address = idaapi.next_not_tail(current_address)

class NodeCoverage(object):
    """
    Manage coverage data at the node (basic block) level.

    TODO
    """
    def __init__(self, node_metadata):
        self.address = node_metadata.address

    def finalize(self, node_metadata, palette):
        """
        TODO
        """

        # bake colors
        self.coverage_color = 0xFF0000
        #compute_color_on_gradiant(
        #    1.0,                   # 100%, 
        #    palette.coverage_bad,
        #    palette.coverage_good
        #)

        # TODO:
        #self.profiling_color = 0

#------------------------------------------------------------------------------
# Instruction Level Coverage
#------------------------------------------------------------------------------
#
#   TODO: this will be important for profiling data
#

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

def build_function_converage():
    """
    Build a clean function map ready to populate with future coverage.
    """
    functions = {}
    for function_address in idautils.Functions():
        functions[function_address] = FunctionMetadata(function_address)
    return functions

def build_function_coverage2(coverage_blocks):
    """
    Map block based coverage data to database defined basic blocks (nodes).

    -----------------------------------------------------------------------

    NOTE:

      I don't like writing overly large / complex functions. But this
      will be an important high compute + IDB access point for larger
      data sets.

      I put some effort into reducing database access, excessive
      searches, iterations, instantiations, etc. I am concerned about
      performance overhead that may come with trying to break this out
      into multiple functions, but I encourage you to try :-)

    -----------------------------------------------------------------------

    Input:

        +- coverage_blocks:
        |    a list of tuples in (offset, size) format that define coverage
        '
    -----------------------------------------------------------------------

    Output:

        +- function_map:
        |    a map keyed with a function address and holds function coverage
        |
        |      eg: { functionEA: FunctionCoverage(...) }
        |
        +- orphans:
        |    a list of tuples (offset, size) of coverage fragments that could
        |    not be mapped into any defined functions / nodes
        |
        |      eg: [(offset, size), ...]
        '

    """
    function_map, orphans = {}, []

    # TODO
    FLOWCHART_CACHE_SIZE = 6
    flowchart_cache = FlowChartCache(FLOWCHART_CACHE_SIZE)

    #
    # The purpose of this mega while loop is to process the raw block
    # based coverage data and build a comprehensive mapping of nodes
    # throughout the database that are tainted by it.
    #

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
            orphans.append((address, size))
            continue

        # alias the function's address from the flowchart for convenience
        function_address = flowchart.bounds.startEA

        #
        # At this point, we have located the flowchart corresponding to
        # this address. We are now ready to identify which node our
        # current coverage block (address, size) starts in.
        #

        #
        # walk through every node (basic block) in the flowchart until a
        # a node corresponding with our coverage block is found
        #

        flowchart_size = flowchart.size()
        for count in xrange(flowchart_size):

            # get the last basic block we started on
            index = (cached_base + count) % flowchart_size
            bb = flowchart[index]

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
                flowchart_cache.set((flowchart, index))

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

    #
    # We are done processing the coverage data given to us. Now we
    # enumerate and initialize all the functions that had no coverage.
    #

    # NOTE: linear sweep, no reason to use the flowcache here
    for function_address in idautils.Functions():
        if function_address not in function_map:
            function  = idaapi.get_func(function_address)
            flowchart = idaapi.qflow_chart_t("", function, idaapi.BADADDR, idaapi.BADADDR, 0)
            function_map[function_address] = FunctionCoverage(flowchart)

    # done, return results
    return (function_map, orphans)
