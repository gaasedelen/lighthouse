import logging
import weakref
import itertools
import collections

from lighthouse.util import *
from lighthouse.util import compute_color_on_gradiant
from lighthouse.painting import *
from lighthouse.metadata import DatabaseMetadata

logger = logging.getLogger("Lighthouse.Coverage")

#------------------------------------------------------------------------------
# Coverage / Data Mapping
#------------------------------------------------------------------------------
#
#    Raw runtime data (eg, coverage or trace) passed into the director is
#    stored internally in DatabaseCoverage objects. A DatabaseCoverage
#    object can be roughly equated to a single loaded runtime data file.
#
#    DatabaseCoverage objects simply map their raw runtime data to the
#    database using the lifted metadata described in metadata.py. The
#    mapping objects are effectively generated as a thin layer on top of
#    cached metadata.
#
#    As mapping objects retain the raw runtime data internally, we are
#    able to rebuild mappings should the database/metadata get updated or
#    refreshed by the user.
#
#    ----------------------------------------------------------------------
#
#    Note that this file / the mapping structures are still largely a
#    work in progress and likely to change in the near future.
#

#------------------------------------------------------------------------------
# Database Coverage / Data Mapping
#------------------------------------------------------------------------------

class DatabaseCoverage(object):
    """
    Database level coverage mapping.
    """

    def __init__(self, data, palette):

        # color palette for painting mapping data
        self.palette = palette

        # metadata to build mappings on top of
        self._metadata = DatabaseMetadata()

        # hitmap that holds the source data of our mapping
        self._hitmap = build_hitmap(data)

        # a simple hash of the coverage mask (aka self._hitmap.keys())
        self.coverage_hash = 0
        self._update_coverage_hash()

        # maps of the child mapping objects
        self.nodes        = {}
        self.functions    = {}

        # mark all data as unmapped
        self._unmapped_data = set(self._hitmap.keys())
        self._unmapped_data.add(idaapi.BADADDR)

        #
        # profiling revealed that letting every child (eg, FunctionCoverage
        # or NodeCoverage) create their own weakref to the parent/database
        # was actually adding a reasonable and unecessary overhead. There's
        # really no reason they need to do that anyway.
        #
        # we instantiate a single weakref of ourself (the DatbaseMapping
        # object) such that we can distribute it to the children we create
        # without having to repeatedly instantiate new ones.
        #

        self._weak_self = weakref.proxy(self)

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def data(self):
        """
        The data (a hitmap) used by this mapping.
        """
        return self._hitmap

    @property
    def coverage(self):
        """
        The instruction-level coverage mask of this mapping.
        """
        return self._hitmap.viewkeys()

    @property
    def instruction_percent(self):
        """
        The database coverage % by instructions executed in all defined functions.
        """
        try:
            return sum(f.instruction_percent for f in self.functions.itervalues()) / len(self._metadata.functions)
        except ZeroDivisionError:
            return 0.0

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
            self._unmap_delta(delta)

    def refresh(self):
        """
        Refresh the mapping of our coverage data to the database metadata.
        """

        # rebuild our coverage mapping
        dirty_nodes, dirty_functions = self._map_coverage()

        # bake our coverage map
        self._finalize(dirty_nodes, dirty_functions)

    def refresh_nodes(self):
        """
        Special fast-refresh of nodes as used in the un-painting process.
        """
        dirty_nodes = self._map_nodes()
        self._finalize_nodes(dirty_nodes)

    def _finalize(self, dirty_nodes, dirty_functions):
        """
        Finalize coverage objects for use.
        """
        self._finalize_nodes(dirty_nodes)
        self._finalize_functions(dirty_functions)

    def _finalize_nodes(self, dirty_nodes):
        """
        Finalize coverage nodes for use.
        """
        for node_coverage in dirty_nodes.itervalues():
            node_coverage.finalize()

    def _finalize_functions(self, dirty_functions):
        """
        Finalize coverage nodes for use.
        """
        for function_coverage in dirty_functions.itervalues():
            function_coverage.finalize()

    #--------------------------------------------------------------------------
    # Data Operations
    #--------------------------------------------------------------------------

    def add_data(self, data):
        """
        Add runtime data to this mapping.
        """

        # add the given runtime data to our data source
        for address, hit_count in data.iteritems():
            self._hitmap[address] += hit_count

        # update the coverage hash incase the hitmap changed
        self._update_coverage_hash()

        # mark these touched addresses as dirty
        self._unmapped_data |= data.viewkeys()

    def subtract_data(self, data):
        """
        Subtract runtime data from this mapping.
        """

        # subtract the given runtime data from our data source
        for address, hit_count in data.iteritems():
            self._hitmap[address] -= hit_count

            #assert self._hitmap[address] >= 0

            #
            # if there is no longer any hits for this address, delete its
            # entry from the source_data dictonary. we don't want its entry to
            # hang around because we use self._hitmap.viewkeys() as a
            # coverage bitmap.
            #

            if not self._hitmap[address]:
                del self._hitmap[address]

        # update the coverage hash incase the hitmap changed
        self._update_coverage_hash()

        #
        # unmap everything because a complete re-mapping is easier with the
        # current implementation of things
        #

        self._unmap_all()

    #--------------------------------------------------------------------------
    # Coverage Operations
    #--------------------------------------------------------------------------

    def mask_data(self, coverage_mask):
        """
        Mask the hitmap data against a given coverage mask.

        Returns a new DatabaseCoverage containing the masked hitmap.
        """
        composite_data = collections.defaultdict(int)

        # preserve only hitmap data that matches the coverage mask
        for address in coverage_mask:
            composite_data[address] = self._hitmap[address]

        # done, return a new DatabaseCoverage masked with the given coverage
        return DatabaseCoverage(composite_data, self.palette)

    def _update_coverage_hash(self):
        """
        Update the hash of the coverage mask.
        """
        if self._hitmap:
            self.coverage_hash = hash(frozenset(self._hitmap.viewkeys()))
        else:
            self.coverage_hash = 0

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
        Map loaded runtime data to database defined nodes (basic blocks).
        """
        dirty_nodes = {}
        addresses_to_map = collections.deque(sorted(self._unmapped_data))

        #
        # This while loop is the core of our coverage mapping process.
        #
        # The '_unmapped_data' list is consumed by this loop, mapping
        # any unmapped runtime data maintained by this DatabaseCoverage
        # to the given database metadata.
        #
        # It should be noted that the rest of the database coverage
        # mapping (eg functions) gets built ontop of the mappings we build
        # for nodes here using the more or less raw/recycled runtime data.
        #

        while addresses_to_map:

            # get the next address to map
            address = addresses_to_map.popleft()

            # get the node (basic block) that contains this address
            try:
                node_metadata = self._metadata.get_node(address)

            #
            # failed to locate the node (basic block) for this address.
            # this address must not fall inside of a defined function...
            #

            except ValueError:
                continue

            #
            # we found applicable node metadata for this address, now try
            # to find the mapping object for this node address
            #

            if node_metadata.address in self.nodes:
                node_coverage = self.nodes[node_metadata.address]

            #
            # failed to locate a node coverage object, looks like this is
            # the first time we have identiied coverage for this node.
            # create a coverage node object and use it now.
            #

            else:
                node_coverage = NodeCoverage(node_metadata.address, self._weak_self)
                self.nodes[node_metadata.address] = node_coverage

            # compute the basic block end now to reduce overhead in the loop below
            node_end = node_metadata.address + node_metadata.size

            #
            # the loop below can be thought of almost as an inlined fast-path
            # where we expect the next several addresses to belong to the same
            # node (basic block).
            #
            # with the assumption of linear program execution, we can reduce
            # the heavier overhead of all the lookup code above by simply
            # checking if the next address in the queue (addresses_to_map)
            # falls into the same / current node (basic block).
            #
            # we can simply re-use the current node and its coverage object
            # until the next address to be processed falls outside our scope
            #

            while 1:

                # map the hitmap data for the current address to this node mapping
                node_coverage.executed_instructions[address] = self._hitmap[address]
                self._unmapped_data.discard(address)

                # get the next address to attempt mapping on
                address = addresses_to_map.popleft()

                #
                # if the next address is not in this node, it's time break out
                # of this loop and send it through the full node lookup path
                #

                if not (node_metadata.address <= address < node_end):
                    addresses_to_map.appendleft(address)
                    break

                #
                # the next address to be mapped DOES fall within our current
                # node, loop back around in the fast-path and map it
                #

                # ...

            # since we updated this node, ensure we're tracking it as dirty
            dirty_nodes[node_metadata.address] = node_coverage

        # done
        return dirty_nodes

    def _map_functions(self, dirty_nodes):
        """
        Map loaded coverage data to database defined functions.
        """
        dirty_functions = {}

        #
        # thanks to the _map_nodes function, we now have a repository of
        # node coverage objects that are considered 'dirty' and can be used
        # precisely guide the generation of our function level coverage
        #

        for node_coverage in dirty_nodes.itervalues():

            #
            # using the node_coverage object, we retrieve its underlying
            # metadata so that we can perform a reverse lookup of the fun
            #

            function_metadata = self._metadata.nodes[node_coverage.address].function

            #
            # now we can add this node to its respective function level
            # coverage mapping
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

            # mark this node as executed in the function level mappping
            function_coverage.mark_node(node_coverage)
            dirty_functions[function_metadata.address] = function_coverage

            # end of nodes loop

        # done
        return dirty_functions

    def _unmap_all(self):
        """
        Unmap all mapped data.
        """
        self._unmapped_data = set(self._hitmap.keys())
        self._unmapped_data.add(idaapi.BADADDR)
        self.nodes        = {}
        self.functions    = {}

    def _unmap_delta(self, delta):
        """
        Unmap node & function coverage affected by the metadata delta.

        The metadata delta tells us exactly which parts of the database
        changed since our last coverage mapping. This function surgically
        unmaps the pieces of our coverage that may now be stale.

        This enables us to recompute only what is necessary upon refresh.
        """
        self._unmap_nodes(itertools.chain(delta.nodes_removed, delta.nodes_modified))
        self._unmap_functions(delta.functions_removed)

    def _unmap_nodes(self, node_addresses):
        """
        Unmap any data associated with a given list of node addresses.
        """

        #
        # using the metdata delta as a guide, we loop through all the nodes it
        # has noted as either modified, or deleted. it is in our best interest
        # unmap any of these dirty (stale) node addresses in OUR coverage
        # mapping so we can selectively regenerate their coverage later.
        #

        for node_address in node_addresses:

            #
            # if there's no coverage for this node, then we have nothing to do.
            # continue on to the next dirty node address
            #

            node_coverage = self.nodes.pop(node_address, None)
            if not node_coverage:
                continue

            # the node was found, unmap any of its tracked coverage blocks
            self._unmapped_data.update(
                node_coverage.executed_instructions.viewkeys()
            )


    def _unmap_functions(self, function_addresses):
        """
        Unmap any data associated with a given list of function addresses.
        """
        for function_address in function_addresses:
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
        self.nodes = {}

        # compute the # of instructions executed by this function's coverage
        self.instruction_percent = 0.0
        self.node_percent = 0.0

        # baked colors
        if function_address == idaapi.BADADDR:
            self.coverage_color = QtGui.QColor(30, 30, 30)
        else:
            self.coverage_color = 0

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def hits(self):
        """
        The cumulative instruction executions in this function.
        """
        return sum(x.hits for x in self.nodes.itervalues())

    @property
    def nodes_executed(self):
        """
        The number of nodes executed in this function.
        """
        return len(self.nodes)

    @property
    def instructions_executed(self):
        """
        The number of unique instructions executed in this function.
        """
        return sum(x.instructions_executed for x in self.nodes.itervalues())

    @property
    def instructions(self):
        """
        The instruction addresses in this function.
        """
        return set([ea for node in self.nodes.itervalues() for ea in node.executed_instructions.keys()])

    #--------------------------------------------------------------------------
    # Controls
    #--------------------------------------------------------------------------

    def mark_node(self, node_coverage):
        """
        Mark the given node address as executed.
        """
        self.nodes[node_coverage.address] = node_coverage

    def finalize(self):
        """
        Finalize coverage data for use.
        """
        palette = self._database.palette
        function_metadata = self._database._metadata.functions[self.address]

        # compute the % of nodes executed
        self.node_percent = float(self.nodes_executed) / function_metadata.node_count

        # compute the % of instructions executed
        self.instruction_percent = float(self.instructions_executed) / function_metadata.instruction_count

        # the estimated number of executions this function has experienced
        self.executions = float(sum(x.executions for x in self.nodes.itervalues())) / function_metadata.node_count

        # bake colors
        self.coverage_color = compute_color_on_gradiant(
            self.instruction_percent,
            palette.coverage_bad,
            palette.coverage_good
        )

#------------------------------------------------------------------------------
# Node Coverage / Data Mapping
#------------------------------------------------------------------------------

class NodeCoverage(object):
    """
    Node (basic block) level coverage mapping.
    """

    def __init__(self, node_address, database=None):
        self._database = database
        self.address = node_address
        self.executed_instructions = {}

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def hits(self):
        """
        The cumulative instruction executions in this node.
        """
        return sum(self.executed_instructions.itervalues())

    @property
    def instructions_executed(self):
        """
        The number of unique instructions executed in this node.
        """
        return len(self.executed_instructions)

    #--------------------------------------------------------------------------
    # Controls
    #--------------------------------------------------------------------------

    def finalize(self):
        """
        Finalize the coverage metrics for faster access.
        """
        palette = self._database.palette
        node_metadata = self._database._metadata.nodes[self.address]

        # the estimated number of executions this node has experienced.
        self.executions = float(self.hits) / node_metadata.instruction_count

        # bake colors
        self.coverage_color = palette.ida_coverage

