import bisect
import logging

import idaapi
import idautils

from lighthouse.util import *

logger = logging.getLogger("Lighthouse.Metadata")

#------------------------------------------------------------------------------
# Database Level Metadata
#------------------------------------------------------------------------------

class DatabaseMetadata(object):
    """
    Fast access database level metadata cache.
    """

    def __init__(self):

        # database defined nodes (basic blocks)
        self.nodes = {}
        self._node_addresses = []

        # database defined functions
        self.functions = {}
        self._function_addresses = []

        # TODO: database defined segments
        #self.segments = {}
        #self._segment_addresses = {}

        self._build_metadata()

    #----------------------------------------------------------------------
    # Providers
    #----------------------------------------------------------------------

    def get_node(self, address):
        """
        Get the node (basic block) for a given address.

        This function provides fast lookup of node metadata for an
        arbitrary address (ea). Assuming the address falls within a
        defined function, there should exist a graph node for it.

        We use bisection across the defined node (basic block) addresses
        to perform a fuzzy lookup of the closest block just prior to the
        target address.

        If the target address falls within the selected node, the node's
        metadata is returned. Otherwise, a ValueError is raised.
        """

        #
        # TODO/NOTE/PERF:
        #
        #   sortedcontainers.SortedDict would be ideal type for the nodes and
        #   functions dictionaries. It means we wouldn't have to maintain an
        #   entirely seperate list of addresses for quick bisection.
        #
        #   but I don't want to hassle people with a dependency on an external
        #   package for lightouse. so we'll keep it in-house and old school.
        #

        #found = self.nodes.iloc[(self.nodes.bisect_left(address) - 1)]

        # locate the index of the closest cached node address (rounding down)
        node_index = bisect.bisect_right(self._node_addresses, address) - 1

        # if the identified node contains our target address, it is a match
        try:
            node = self.nodes[self._node_addresses[node_index]]
            if node.address <= address < node.address + node.size:
                return node
        except KeyError:
            pass

        #
        # if the selected node was not a match, there are no second chances.
        # the address simply does not exist within a defined node.
        #

        raise ValueError("Given address does not fall within a known node")

    #----------------------------------------------------------------------
    # Controls
    #----------------------------------------------------------------------

    def refresh(self):
        """
        Refresh database metadata.
        """
        pass

    def finalize(self):
        """
        Finalize database metadata for faster access.
        """
        pass

    #----------------------------------------------------------------------
    # Metadata Population
    #----------------------------------------------------------------------

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

            # bake elements of the function metadata for faster future use
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
        # respective dict. c.f:
        #
        #   - get_node(ea)
        #   - get_function(ea)
        #

        self._node_addresses     = sorted(self.nodes.keys())
        self._function_addresses = sorted(self.functions.keys())

        # done

#------------------------------------------------------------------------------
# Function Level Metadata
#------------------------------------------------------------------------------

class FunctionMetadata(object):
    """
    Fast access function level metadata cache.
    """

    def __init__(self, address):

        # function metadata
        self.address = address
        self.name    = idaapi.get_func_name2(address)

        # node metadata
        self.nodes = {}

        # fixed ('baked') metrics
        self.size = 0
        self.node_count = 0
        self.instruction_count = 0

    #----------------------------------------------------------------------
    # Properties
    #----------------------------------------------------------------------

    @property
    def live_size(self):
        """
        The size of the function in bytes (by node contents).
        """
        return sum(node.size for node in self.nodes.itervalues())

    @property
    def live_node_count(self):
        """
        The number of nodes in this function.
        """
        return len(self.nodes)

    @property
    def live_instruction_count(self):
        """
        The number of instructions in this function.
        """
        return sum(node.instruction_count for node in self.nodes.itervalues())

    #----------------------------------------------------------------------
    # Controls
    #----------------------------------------------------------------------

    def refresh(self):
        """
        Refresh function metadata.
        """
        self._refresh_name()
        self._refresh_nodes()

    def finalize(self):
        """
        Finalize function metadata for faster access.
        """
        self.size = self.live_size
        self.node_count = self.live_node_count
        self.instruction_count = self.live_instruction_count

    #----------------------------------------------------------------------
    # Metadata Population
    #----------------------------------------------------------------------

    def _refresh_name(self):
        """
        Refresh the function name against the open IDB.
        """
        self.name = idaapi.get_func_name2(self.address)

    def _refresh_nodes(self):
        """
        Refresh the function nodes against the open IDB.
        """

        # get function & flowchart object from IDB
        function  = idaapi.get_func(self.address)
        flowchart = idaapi.qflow_chart_t("", function, idaapi.BADADDR, idaapi.BADADDR, 0)

        # dispose of stale information
        self.nodes = {}

        #
        # iterate through every node (basic block) in the flowchart for a given
        # function so that we may build node level metadata
        #

        for node_id in xrange(flowchart.size()):

            # first, create a new node coverage item for this node
            new_node = NodeMetadata(flowchart[node_id])
            new_node.ids[self.address] = node_id

            # build a relation between the node, and this function (self)
            new_node.functions[self.address] = self

            # build a relation between this function, and the node
            self.nodes[new_node.address] = new_node

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def name_changed(self, new_name):
        """
        Handler for rename event in IDA.

        TODO: hook this up
        """
        self.name = new_name

#------------------------------------------------------------------------------
# Node Level Metadata
#------------------------------------------------------------------------------

class NodeMetadata(object):
    """
    Fast access node level metadata cache.
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

    #----------------------------------------------------------------------
    # Controls
    #----------------------------------------------------------------------

    def refresh(self):
        """
        TODO
        """

        # loop through the node's entire range and count its instructions
        current_address = self.address
        while current_address < self.address + self.size:
            self.instruction_count += 1
            current_address = idaapi.next_not_tail(current_address)

#------------------------------------------------------------------------------
# Instruction Level Metadata
#------------------------------------------------------------------------------

class InstructionMetadata(object):
    """
    Fast access instruction level metadata cache.
    TODO: this will be important when profiling is implemented
    """

    def __init__(self, address):
        pass
