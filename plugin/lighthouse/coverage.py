import logging
import weakref
import itertools
import collections

from lighthouse.util import *
from lighthouse.util.qt import QtGui #TODO remove
from lighthouse.palette import compute_color_on_gradiant
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
#    'mapping' objects detailed in this file are effectively produced as
#    a thin layer on top of cached metadata.
#
#    As mapping objects retain the raw runtime data internally, we are
#    able to rebuild mappings should the database/metadata get updated or
#    refreshed by the user.
#

BADADDR = 0xFFFFFFFFFFFFFFFF

#------------------------------------------------------------------------------
# Database Coverage / Data Mapping
#------------------------------------------------------------------------------

class DatabaseCoverage(object):
    """
    Database level coverage mapping.
    """

    def __init__(self, data, palette):

        # color palette
        self.palette = palette

        #
        # the abstract above gives some background to the design employed by
        # Lighthouse to map coverage data to the database.
        #
        # coverage objects such as this (DatabaseCoverage) are basically
        # glorified mappings of coverage / runtime data on top of their
        # metadata counterparts. A coverage object by itself is mostly useless
        # without its corresponding metadata object.
        #
        # here we simply populate self._metadata with a stub metadata object,
        # but at runtime we will inject a fully collected DatabaseMetadata
        # object as maintained by the director.
        #

        self._metadata = DatabaseMetadata()

        #
        # the hitmap effectively holds the raw coverage data. the name
        # should speak for itself, but a hitmap will track the number of
        # times a given address / instruction was executed.
        #
        #  Eg:
        #      hitmap =
        #      {
        #          0x8040100: 1,
        #          0x8040102: 1,
        #          0x8040105: 3,
        #          0x8040108: 3,  # 0x8040108 was executed 3 times...
        #          0x804010a: 3,
        #          0x804010f: 1,
        #          ...
        #      }
        #
        # this structure gives us an interesting degree of flexibility with
        # regard to what data sources we can consue (inst trace, coverage, etc)
        # and ways we can leverage said data (visualize coverage, heatmaps)
        #

        self._hitmap = build_hitmap(data)

        #
        # the coverage hash is a simple hash of the coverage bitmap/mask.
        # it is primarily used by the director as a means of quickly comparing
        # coverage, and predicting outputs of logical / arithmetic operations.
        #
        # the hash will need to be updated via _update_coverage_hash() anytime
        # the hitmap is modified or changed internally. we cache a concrete
        # result of the coverage hash because computing the hash on demand can
        # be expensive in terms of time.
        #
        # see the usage of 'coverage_hash' in director.py for more info
        #

        self.coverage_hash = 0
        self._update_coverage_hash()

        #
        # Lighthouse will only compute coverage for code within defined
        # functions. therefore, all coverage / runtime data will get bucketed
        # into its appropriate NodeCoverage object (eg, a basic block) or it
        # will be considered 'unmapped'
        #
        # starting out, all coverage data is marked as unmapped
        #

        self._unmapped_data = set(self._hitmap.keys())
        self._unmapped_data.add(BADADDR)

        #
        # self._map_coverage is responsible for mapping coverage data to the
        # database (via the lifted 'DatabaseMetadata' cache). The mapping
        # process will yield NodeCoverage & FunctionCoverage objects.
        #
        # NodeCoverage objects represent coverage at the node (basic block)
        # level and are owned by their respective FunctionCoverage objects.
        #
        # FunctionCoverage represent coverage at the function level by
        # leveraging their respective NodeCoverage children.
        #

        self.nodes     = {}
        self.functions = {}
        self.instruction_percent = 0.0

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
        The instruction-level coverage bitmap/mask of this mapping.
        """
        return self._hitmap.viewkeys()

    #--------------------------------------------------------------------------
    # Metadata Population
    #--------------------------------------------------------------------------

    def update_metadata(self, metadata, delta=None):
        """
        Install a new databasee metadata object.
        """

        # install the new metadata
        self._metadata = weakref.proxy(metadata)
        self.unmap_all()

    def refresh(self):
        """
        Refresh the mapping of our coverage data to the database metadata.
        """

        # rebuild our coverage mapping
        dirty_nodes, dirty_functions = self._map_coverage()

        # bake our coverage map
        self._finalize(dirty_nodes, dirty_functions)

        # update the coverage hash incase the hitmap changed
        self._update_coverage_hash()

        # dump the unmappable coverage data
        #self.dump_unmapped()

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
        self._finalize_instruction_percent()

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

    def _finalize_instruction_percent(self):
        """
        Finalize the database coverage % by instructions executed in all defined functions.
        """

        # sum all the instructions in the database metadata
        total = sum(f.instruction_count for f in self._metadata.functions.itervalues())
        if not total:
            self.instruction_percent = 0.0
            return

        # sum all the instructions executed by the coverage
        executed = sum(f.instructions_executed for f in self.functions.itervalues())

        # return the average function coverage % aka 'the database coverage %'
        self.instruction_percent = float(executed) / total

    #--------------------------------------------------------------------------
    # Data Operations
    #--------------------------------------------------------------------------

    def add_data(self, data, update=True):
        """
        Add runtime data to this mapping.
        """

        # add the given runtime data to our data source
        for address, hit_count in data.iteritems():
            self._hitmap[address] += hit_count

        # do not update other internal structures if requested
        if not update:
            return

        # update the coverage hash incase the hitmap changed
        self._update_coverage_hash()

        # mark these touched addresses as dirty
        self._unmapped_data |= data.viewkeys()

    def add_addresses(self, addresses, update=True):
        """
        Add a list of instruction addresses to this mapping (eg, a trace).
        """

        # increment the hit count for an address
        for address in addresses:
            self._hitmap[address] += 1

        # do not update other internal structures if requested
        if not update:
            return

        # update the coverage hash incase the hitmap changed
        self._update_coverage_hash()

        # mark these touched addresses as dirty
        self._unmapped_data |= set(addresses)

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
            # coverage bitmap/mask
            #

            if not self._hitmap[address]:
                del self._hitmap[address]

        # update the coverage hash incase the hitmap changed
        self._update_coverage_hash()

        #
        # unmap everything because a complete re-mapping is easier with the
        # current implementation of things
        #

        self.unmap_all()

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
            node_metadata = self._metadata.get_node(address)

            #
            # failed to locate the node (basic block) for this address.
            # this address must not fall inside of a defined function...
            #

            if not node_metadata:
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

                #
                # map the hitmap data for the current address (an instruction)
                # to this node mapping and mark the instruction as mapped by
                # discarding its address from the unmapped data list
                #

                if address in node_metadata.instructions:
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

            function_coverage = self.functions.get(function_metadata.address, None)

            #
            # if we failed to locate a function coverage object, it means
            # that this is the first time we have identified coverage for this
            # function. create a new coverage function object and use it now.
            #

            if not function_coverage:
                function_coverage = FunctionCoverage(function_metadata.address, self._weak_self)
                self.functions[function_metadata.address] = function_coverage

            # mark this node as executed in the function level mappping
            function_coverage.mark_node(node_coverage)
            dirty_functions[function_metadata.address] = function_coverage

            # end of nodes loop

        # done
        return dirty_functions

    def unmap_all(self):
        """
        Unmap all mapped data.
        """
        self._unmapped_data = set(self._hitmap.keys())
        self._unmapped_data.add(BADADDR)
        self.nodes     = {}
        self.functions = {}

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

    #--------------------------------------------------------------------------
    # Debug
    #--------------------------------------------------------------------------

    def dump_unmapped(self):
        """
        Dump the unmapped coverage data.
        """
        lmsg("Unmapped Coverage:")
        for address in self._unmapped_data:
            lmsg(" * 0x%X" % address)

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
        if function_address == BADADDR:
            self.coverage_color = QtGui.QColor(30, 30, 30) #TODO: remove
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
        function_metadata = self._database._metadata.functions[self.address]

        # compute the % of nodes executed
        self.node_percent = float(self.nodes_executed) / function_metadata.node_count

        # compute the % of instructions executed
        self.instruction_percent = \
            float(self.instructions_executed) / function_metadata.instruction_count

        # the sum of node executions in this function
        node_sum = sum(x.executions for x in self.nodes.itervalues())

        # the estimated number of executions this function has experienced
        self.executions = float(node_sum) / function_metadata.node_count

        # bake colors
        self.coverage_color = compute_color_on_gradiant(
            self.instruction_percent,
            self._database.palette.coverage_bad,
            self._database.palette.coverage_good
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

