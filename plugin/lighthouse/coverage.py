import logging
import collections

from lighthouse.util import *
from lighthouse.util import compute_color_on_gradiant
from lighthouse.painting import *

logger = logging.getLogger("Lighthouse.Coverage")

#------------------------------------------------------------------------------
# Coverage
#------------------------------------------------------------------------------
#
#    The primary role of the director is to centralize the loaded coverage
#    and provide a platform for researchers to explore the relationship
#    between multiple coverage sets.
#
#    Raw coverage data passed into the director is stored internally in
#    DatabaseCoverage objects. A DatabaseCoverage object can be roughly
#    equated to a loaded coverage file as it maps to the open database.
#
#    DatabaseCoverage objects simply map their raw coverage data to the
#    database using the lifted metadata described in metadata.py. The
#    coverage objects are effectively generated as a thin layer on top of
#    cached metadata.
#
#    As coverage objects retain the raw coverage data internally, we are
#    able to rebuild coverage mappings should the database/metadata get
#    updated or refreshed by the user.
#
#    ----------------------------------------------------------------------
#
#    Note that this file / the coverage structures are still largely a
#    work in progress and likely to change in the near future.
#

#------------------------------------------------------------------------------
# Database Level Coverage
#------------------------------------------------------------------------------

class DatabaseCoverage(object):
    """
    Database level coverage mapping.
    """

    def __init__(self, base, coverage_data, palette):

        #
        # for now, we simply pass in the 'global' Lighthouse palette
        # to each database level coverage object. But in the future,
        # perhaps we will want to paint coverages with unique palettes.
        #

        self._palette = palette

        #
        # here we effectively translate the raw block based coveage from
        # (offset,size) to (base+offset,size), effectively baking them
        # into absolute addresses.
        #
        # this was originally done for perfomance concerns such that every
        # usage of a block from the 'raw' coverage data required a compute
        # of offset+size to get its 'usable' address.
        #
        # this may be refactored in the future
        #

        self._base = base
        self._coverage_data = bake_coverage_addresses(base, coverage_data)

        # maps for the child coverage objects
        self.nodes     = {}
        self.functions = {}

        # a list of orphan coverage blocks that could NOT be mapped to
        # defined functions or nodes in the database
        self.orphans = []

    #----------------------------------------------------------------------
    # Metadata Population
    #----------------------------------------------------------------------

    def refresh(self, db_metadata):
        """
        Refresh the mapping of our coverage data to the database metadata.
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

    def _map_nodes(self, db_metadata):
        """
        Map loaded coverage data to database defined nodes (basic blocks).
        """
        assert self.nodes == {}

        #
        # The purpose of this mega while loop is to process the raw block
        # based coverage data wrapped by this DatabaseCoverage object and
        # build a comprehensive mapping of this data to nodes (basic
        # blocks) as defined by the given database metadata
        #
        # It should be noted that the rest of the database coverage
        # mapping (eg functions) gets built ontop of the mappings we build
        # for nodes here using the raw coverage data.
        #

        blocks = collections.deque(self._coverage_data)
        while blocks:

            # retrieve the next coverage block to map to the database
            address, size = blocks.popleft()

            # why would you have a zero size block?!?
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
            #    address --> address+size may contain the start of a
            #    nearby node, so we might actually skip some stuff here...
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

            # does the coverage block spill past this node??
            coverage_end = address + size
            node_end     = node_metadata.address + node_metadata.size
            if node_end < coverage_end:

                #
                # yes this coverage block spills into the next node,
                # compute the size of this fragment and prepend the work
                # to be processed later (the next iteration, technically)
                #

                fragment_address = node_end
                fragment_size    = coverage_end - node_end
                blocks.appendleft((fragment_address, fragment_size))

        # end of blocks loop

        # done
        return

    def _map_functions(self, db_metadata):
        """
        Map loaded coverage data to database defined functions.
        """
        assert self.functions == {}

        #
        # thanks to the _map_nodes function, we now have a repository of
        # node coverage objects (self.nodes) that can be used to preciesly
        # guide the generation of our function level coverage objects
        #

        #
        # we loop through every node coverage object
        #

        for node_coverage in self.nodes.itervalues():

            #
            # using the node_coverage object, we retrieve its underlying
            # metadata so that we can perform a reverse lookup of all the
            # functions in the database that reference this node
            #

            functions = db_metadata.nodes[node_coverage.address].functions

            #
            # now we can loop through every function that references this
            # node and initialize or add this node to its respective
            # coverage mapping
            #

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
                    function_coverage = FunctionCoverage(function_metadata.address)
                    self.functions[function_metadata.address] = function_coverage

                #
                # finally, we can taint this node in the function level mapping
                #

                function_coverage.mark_node(node_coverage)

                # end of functions loop

            # end of nodes loop

        # done
        return

#------------------------------------------------------------------------------
# Function Level Coverage
#------------------------------------------------------------------------------

class FunctionCoverage(object):
    """
    Function level coverage mapping.
    """

    def __init__(self, function_address):
        self.address = function_address

        # addresses of nodes executed
        self.executed_nodes = {}

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

        # compute the % of instructions executed
        self.instruction_percent = float(self.instructions_executed) / function_metadata.instruction_count

        # compute the number of nodes executed
        self.nodes_executed = len(self.executed_nodes)

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

class NodeCoverage(object):
    """
    Node (basic block) level coverage mapping.

    NOTE:

      At the moment this class is pretty bare and arguably unecessary. But
      I have faith that it will find its place as Lighthouse matures and
      features such as profiling / hit tracing are explicitly added.

    """

    def __init__(self, node_metadata): # TODO: change to node address?
        self.address = node_metadata.address

    def finalize(self, node_metadata, palette):
        """
        TODO
        """

        # bake colors
        self.coverage_color = palette.ida_coverage
        #self.profiling_color = 0 # TODO

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

