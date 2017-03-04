import logging
import collections

from lighthouse.util import *
from lighthouse.util import compute_color_on_gradiant
from lighthouse.painting import *

logger = logging.getLogger("Lighthouse.Coverage")

#------------------------------------------------------------------------------
# Database Level Coverage
#------------------------------------------------------------------------------

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
# TODO
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
# TODO
#------------------------------------------------------------------------------

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

