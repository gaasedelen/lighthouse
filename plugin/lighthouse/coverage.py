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
# Coverage
#------------------------------------------------------------------------------
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

    def __init__(self, base, indexed_data, palette):


        # the color palette used when painting this coverage
        self.palette = palette

        if not indexed_data:
            indexed_data = collections.defaultdict(int)

        self._base = base
        self.coverage_data = indexed_data
        self.unmapped_coverage = set(indexed_data.keys())
        self.unmapped_coverage.add(idaapi.BADADDR)

        # the metadata this coverage will be mapped to
        self._metadata = DatabaseMetadata(False)

        # maps to the child coverage objects
        self.nodes     = {}
        self.functions = {}

        #
        # profiling revealed that letting every child (eg, FunctionCoverage
        # or NodeCoverage) create their own weakref to the parent/database
        # was actually adding a reasonable and unecessary overhead. There's
        # really no reason they need to do that anyway.
        #
        # we instantiate a single weakref of ourself (the DatbaseCoverage
        # object) such that we can distribute it to the children we create
        # without having to repeatedly instantiate new ones.
        #

        self._weak_self = weakref.proxy(self)

    #--------------------------------------------------------------------------
    # Operator Overloads
    #--------------------------------------------------------------------------

    @property
    def instruction_percent(self):
        """
        The coverage % by instructions executed.
        """
        try:
            return sum(f.instruction_percent for f in self.functions.itervalues()) / len(self._metadata.functions)
        except ZeroDivisionError:
            return 0.0

    #--------------------------------------------------------------------------
    # Operator Overloads
    #--------------------------------------------------------------------------

    def __or__(self, other):
        """
        Overload of '|' (logical or) operator.
        """

        if other is None:
            other = DatabaseCoverage(self._base, None, self.palette)
        elif not isinstance(other, DatabaseCoverage):
            raise NotImplementedError("Cannot OR DatabaseCoverage against type '%s'" % type(other))

        # initialize
        composite_data = collections.defaultdict(int)

        #----------------------------------------------------------------------

        # TODO / v0.4.0: this will be refactored as a 'coverage add/or'

        # compute the union of the two coverage sets
        for address, hit_count in self.coverage_data.iteritems():
            composite_data[address]  = hit_count
        for address, hit_count in other.coverage_data.iteritems():
            composite_data[address] += hit_count

        # done
        return DatabaseCoverage(self._base, composite_data, self.palette)

    def __and__(self, other):
        """
        Overload of '&' (logical and) operator.
        """

        if other is None:
            other = DatabaseCoverage(self._base, None, self.palette)
        elif not isinstance(other, DatabaseCoverage):
            raise NotImplementedError("Cannot AND DatabaseCoverage against type '%s'" % type(other))

        # initialize the object
        composite_data = collections.defaultdict(int)

        #----------------------------------------------------------------------

        # compute the intersecting addresses of the two coverage sets
        intersected_addresses = self.coverage_data.viewkeys() & other.coverage_data.viewkeys()

        # TODO / v0.4.0: this will be refactored as a 'coverage and'

        # accumulate the hit counters for the intersecting coverage
        for address in intersected_addresses:
            composite_data[address] = self.coverage_data[address] + other.coverage_data[address]

        # done
        return DatabaseCoverage(self._base, composite_data, self.palette)

    def __sub__(self, other):
        """
        Overload of '-' (subtract) operator.
        """

        if other is None:
            other = DatabaseCoverage(self._base, None, self.palette)
        elif not isinstance(other, DatabaseCoverage):
            raise NotImplementedError("Cannot SUB DatabaseCoverage against type '%s'" % type(other))

        # initialize the object
        composite_data = collections.defaultdict(int)

        #----------------------------------------------------------------------

        # compute the difference addresses of the two coverage sets
        difference_addresses = self.coverage_data.viewkeys() - other.coverage_data.viewkeys()

        #
        # NOTE:
        #   I'm not convinced I should acumulate the subtractee's hit counts,
        #   and I don't think it makes sense to? so for now we don't.
        #
        # TODO / v0.4.0: this will be refactored as a 'coverage subtract'
        #

        # build the new coverage data
        for address in difference_addresses:
            composite_data[address] = self.coverage_data[address] #- other.coverage_data[address]

        # done
        return DatabaseCoverage(self._base, composite_data, self.palette)

    def hitmap_subtract(self, other):
        """
        Subtract hitmaps from each other.

        TODO: dirty hack that will be removed in v0.4.0
        """

        if other is None:
            other = DatabaseCoverage(self._base, None, self.palette)
        elif not isinstance(other, DatabaseCoverage):
            raise NotImplementedError("Cannot SUB DatabaseCoverage hitmap against type '%s'" % type(other))

        # initialize the object
        composite_data = collections.defaultdict(int)

        #----------------------------------------------------------------------

        # build the new coverage data
        for address in self.coverage_data.viewkeys():
            composite_data[address] = self.coverage_data[address]
        for address in other.coverage_data.viewkeys():
            composite_data[address] -= other.coverage_data[address]
            if not composite_data[address]:
                del composite_data[address]

        # done
        return DatabaseCoverage(self._base, composite_data, self.palette)

    def __xor__(self, other):
        """
        Overload of '^' xor operator.
        """

        if other is None:
            other = DatabaseCoverage(self._base, None, self.palette)
        elif not isinstance(other, DatabaseCoverage):
            raise NotImplementedError("Cannot XOR DatabaseCoverage against type '%s'" % type(other))

        # initialize the object
        composite_data = collections.defaultdict(int)

        #----------------------------------------------------------------------

        # compute the symmetric difference (xor) between two coverage sets
        xor_addresses = self.coverage_data.viewkeys() ^ other.coverage_data.viewkeys()

        # accumulate the hit counters for the xor'd coverage
        for address in xor_addresses & self.coverage_data.viewkeys():
            composite_data[address] = self.coverage_data[address]
        for address in xor_addresses & other.coverage_data.viewkeys():
            composite_data[address] = other.coverage_data[address]

        # done
        return DatabaseCoverage(self._base, composite_data, self.palette)

    def __ror__(self, other):
        return self.__or__(other)

    def __rand__(self, other):
        return self.__and__(other)

    #def __rsub__(self, other):
    #    return self.__sub__(other)

    def __rxor__(self, other):
        return self.__xor__(other)

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
        addresses_to_map = collections.deque(sorted(self.unmapped_coverage))

        #
        # This while loop is the core of our coverage mapping process.
        #
        # The 'unmapped_coverage' list is consumed by this loop, mapping
        # any unmapped coverage data maintained by this DatabaseCoverage
        # to the given database metadata.
        #
        # It should be noted that the rest of the database coverage
        # mapping (eg functions) gets built ontop of the mappings we build
        # for nodes here using the more or less raw/recycled coverage data.
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
            # to find the coverage object for this node address
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

                # map the coverage data for the current address to this node
                node_coverage.executed_bytes.add(address)

                #
                # ownership has been transfered to node_coverage, so this
                # address is no longer considered 'unmapped'
                #

                self.unmapped_coverage.discard(address)

                # get the next address to attempt mapping on
                address = addresses_to_map.popleft()

                #
                # if the address is not in this node, it's time break out of
                # this loop and sned it back through the full node lookup path
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
            # metadata so that we can perform a reverse lookup of all the
            # functions in the database that reference it
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

                # mark this node as executed in the function level mappping
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
            self.unmapped_coverage.update(node_coverage.executed_bytes)

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
        self.executed_bytes = set()

    #--------------------------------------------------------------------------
    # Controls
    #--------------------------------------------------------------------------

    def finalize(self):
        """
        Finalize the coverage metrics for faster access.
        """
        palette = self._database.palette
        #node_coverage = self._database._metadata.nodes[self.address]

        # bake colors
        self.coverage_color = palette.ida_coverage
        #self.profiling_color = 0 # TODO

