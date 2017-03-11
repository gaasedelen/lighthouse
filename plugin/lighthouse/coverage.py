import logging
import weakref
import itertools
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

        # the metadata this coverage will be mapped ontop of
        self._metadata = None

        # the color palette used when painting this coverage
        self.palette = palette

        #
        # translate the raw block based coveage from (offset, size) to
        # (base + offset, size), effectively producing absolute addresses
        #

        self._base = base
        self.unmapped_blocks = collections.deque(bake_coverage_addresses(base, coverage_data))

        # maps for the child coverage objects
        self.nodes     = {}
        self.functions = {}

        #
        # profiling revealed that letting every child (eg, FunctionCoverage
        # or NodeCoverage) create their own weakref to the parent/database
        # was actually adding a reasonable and unecessary overhead.
        #
        # we instantiate a single weakref of ourself (the DatbaseCoverage
        # object) such that we can distribute it to the children we create
        # without having to repeatedly instantiate new ones.
        #

        self._weak_self = weakref.proxy(self)

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def coverage_data(self):
        """
        The coverage data in (address, size) block format.

        This is returned as an iterator.
        """

        #
        # TODO:
        #
        #   I admit, this level of code/python obscurity is both unruly
        #   and uncharacteristic of me. it should be de-obfuscated
        #

        #
        # The objective of this code is to create an abstract iterator
        # 'coverage_data' which will enumerate every piece of coverage
        # data tracked by this DatabaseCoverage object.
        #
        # What makes this so obscure is my attempt to chain and flatten
        # multiple iterators. 'mapped_blocks' is an abstract iterator
        # to enumerate all of the blocks mapped by this coverage.
        #
        # We then chain the mapped_blocks iterator with the unmapped_blocks
        # iterator, to create a complete enumeration of the 'raw' coverage
        # data in this DatabaseeCoverage.
        #

        mapped_blocks = itertools.chain.from_iterable((node_coverage.blocks for node_coverage in self.nodes.itervalues()))
        coverage_data = itertools.chain(self.unmapped_blocks, mapped_blocks)

        # return the uber iterator of all tracked coverage data
        return coverage_data

    #----------------------------------------------------------------------
    #--------------------------------------------------------------------------
    # Metadata Population
    #--------------------------------------------------------------------------

    def update_metadata(self, metadata, delta=None):
        """
        Update the installed metadata.
        """

        # install the new metadata
        self._metadata = weakref.proxy(metadata)

        # unmap all the coverage affected by the metadata delta
        if delta:
            self._unmap_dirty(delta)

    def refresh(self):
        """
        Refresh the mapping of our coverage data to the database metadata.
        """

        # rebuild our coverage mapping
        dirty_nodes, dirty_functions = self._map_coverage()

        # bake our coverage map
        self._finalize(dirty_nodes, dirty_functions)

    def _finalize(self, dirty_nodes, dirty_functions):
        """
        Finalize coverage data for use.
        """

        # finalize node level coverage data
        for node_coverage in dirty_nodes.itervalues():
            node_coverage.finalize()

        # finalize function level coverage data
        for function_coverage in dirty_functions.itervalues():
            function_coverage.finalize()

    #--------------------------------------------------------------------------
    # Coverage Mapping
    #--------------------------------------------------------------------------

    def _map_coverage(self):
        """
        Map loaded coverage data to the given database metadata.
        """

        # re-map any unmapped coverage to nodes
        dirty_nodes = self._map_nodes()

        # re-map nodes to functions
        dirty_functions = self._map_functions(dirty_nodes)

        # return the modified objects
        return (dirty_nodes, dirty_functions)

    def _map_nodes(self):
        """
        Map loaded coverage data to database defined nodes (basic blocks).
        """
        dirty_nodes = {}
        blocks_to_map = self.unmapped_blocks
        self.unmapped_blocks = collections.deque()

        #
        # This while loop is the core of our coverage mapping process.
        #
        # The 'unmapped_blocks' list is consumed by this loop, mapping
        # any unmapped coverage data maintained by this DatabaseCoverage
        # to the given database metadata.
        #
        # It should be noted that the rest of the database coverage
        # mapping (eg functions) gets built ontop of the mappings we build
        # for nodes here using the more or less raw/recycled coverage data.
        #

        while blocks_to_map:

            # retrieve the next coverage block to map to the database
            address, size = blocks_to_map.popleft()

            # sanity check - why would you have a zero size block?!?
            assert size, "Size of coverage block must be non-zero"

            # get the node (basic block) that contains this address
            try:
                node_metadata = self._metadata.get_node(address)

            #
            # failed to locate the node (basic block) for this address.
            # this address must not fall inside of a defined function...
            # mark the block as an orphan and move on.
            #
            #  NOTE/TODO:
            #
            #    address --> address+size may contain the start of a
            #    nearby node, so we might actually skip some stuff here...
            #

            except ValueError:
                self.unmapped_blocks.append((address, size))
                continue

            #
            # we found applicable node metadata for this address, now try
            # to find the coverage object for this node address
            #

            try:
                node_coverage = self.nodes[node_metadata.address]

            #
            # failed to locate a node coverage object, looks like this is
            # the first time we have identiied coverage for this node.
            # create a coverage node object and use it now.
            #

            except KeyError as e:
                node_coverage = NodeCoverage(node_metadata.address, self._weak_self)
                self.nodes[node_metadata.address] = node_coverage

            #
            # ensure that the block of coverage data we are trying to map
            # to this node does not actually spill past it. If it does,
            # we need to break it up and generate a 'fragment' coverage
            # block consisting of the remainder.
            #

            coverage_end = address + size
            node_end     = node_metadata.address + node_metadata.size

            # does the coverage block spill past this node??
            if node_end < coverage_end:

                #
                # yes this coverage block spills into the next node,
                # prepend the overflown coverage fragment to be processed
                # later (the next iteration, technically)
                #

                fragment_address = node_end
                fragment_size    = coverage_end - node_end
                blocks_to_map.appendleft((fragment_address, fragment_size))

                #
                # since we split the overflow coverage data into a fragment,
                # the end of the current coverage data block we are mapping
                # actually aligns with the end of this node.
                #

                coverage_end = node_end

            # map the coverage data block to this node
            node_coverage.add_mapping(address, coverage_end-address)

            # since we updated this node, ensure we're tracking it as dirty
            dirty_nodes[node_metadata.address] = node_coverage

        # end of blocks loop

        # done
        return dirty_nodes

    def _map_functions(self, dirty_nodes):
        """
        Map loaded coverage data to database defined functions.
        """
        dirty_functions = {}

        #
        # thanks to the _map_nodes function, we now have a repository of
        # node coverage objects (self.nodes) that can be used to preciesly
        # guide the generation of our function level coverage objects
        #

        #
        # we loop through every node coverage object
        #

        for node_coverage in dirty_nodes.itervalues():

            #
            # using the node_coverage object, we retrieve its underlying
            # metadata so that we can perform a reverse lookup of all the
            # functions in the database that reference this node
            #

            functions = self._metadata.nodes[node_coverage.address].functions

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
                    function_coverage = FunctionCoverage(function_metadata.address, self._weak_self)
                    self.functions[function_metadata.address] = function_coverage

                #
                # finally, we can taint this node in the function level mapping
                #

                function_coverage.mark_node(node_coverage)
                dirty_functions[function_metadata.address] = function_coverage

                # end of functions loop

            # end of nodes loop

        # done
        return dirty_functions

    def _unmap_dirty(self, delta):
        """
        Unmap node & function coverage affected by the metadata delta.

        The metadata delta tells us exactly which parts of the database
        changed since our last coverage mapping. This function surgically
        unmaps the pieces of our coverage that may now be stale.

        This enables us to recompute only what is necessary upon refresh.
        """

        #
        # Dirty Nodes
        #

        #
        # using the metdata delta as a guide, we loop through all the nodes it
        # has noted as either modified, or deleted. it is in our best interest
        # unmap any of these dirty (stale) node addresses in OUR coverage
        # mapping so we can selectively regenerate their coverage later.
        #

        for node_address in itertools.chain(delta.nodes_removed, delta.nodes_modified):

            #
            # if there's no coverage for this node, then we have nothing to do.
            # continue on to the next dirty node address
            #

            node_coverage = self.nodes.pop(node_address, None)
            if not node_coverage:
                continue

            # the node was found, unmap any of its tracked coverage blocks
            self.unmapped_blocks.extend(node_coverage.blocksp

            #
            # NOTE:
            #
            #   since we pop'd node_coverage from the database-wide self.nodes
            #   list, this loop iteration owns the last remaining 'hard' ref to
            #   the object. once the loop rolls over, it will be released.
            #
            #   what is cool about this is that its corresponding entry for
            #   this node_coverage object in any FunctionCoverage objects that
            #   reference this node will also dissapear. This is because the
            #   executed_nodes dictionaries are built using WeakValueDictionary.
            #

        #
        # Dirty Functions
        #

        # delete function coverage objects for the allegedly deleted functions
        for function_address in delta.functions_removed:
            self.functions.pop(function_address, None)


#------------------------------------------------------------------------------
# Function Level Coverage
#------------------------------------------------------------------------------

class FunctionCoverage(object):
    """
    Function level coverage mapping.
    """

    def __init__(self, function_address, database=None):
        self._database = database
        self.address = function_address

        # addresses of nodes executed
        self.executed_nodes = weakref.WeakValueDictionary()

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

    #--------------------------------------------------------------------------
    # Controls
    #--------------------------------------------------------------------------

    def mark_node(self, node_coverage):
        """
        Mark the given node address as executed.
        """
        self.executed_nodes[node_coverage.address] = node_coverage

    def finalize(self):
        """
        Finalize coverage data for use.
        """
        palette = self._database.palette
        function_metadata = self._database._metadata.functions[self.address]

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

    def __init__(self, node_address, database=None):
        self._database = database
        self.address = node_address
        self.blocks = []

    #--------------------------------------------------------------------------
    # TODO
    #--------------------------------------------------------------------------

    def add_mapping(self, address, size):
        """
        Add a given coverage block (address, size) to this nodes mapping.
        """
        self.blocks.append((address, size))

    def finalize(self):
        """
        Finalize the coverage metrics for faster access.
        """
        palette = self._database.palette
        #node_coverage = self._database._metadata.nodes[self.address]

        # coalesce the accumulated coverage blocks
        self.blocks = coalesce_blocks(self.blocks)

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

