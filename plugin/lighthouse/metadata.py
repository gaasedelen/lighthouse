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

        #----------------------------------------------------------------------

        # collect metdata from the underlying database
        self._build_metadata()

        #
        # now that we have collected all the node & function metadata available
        # to us at this time, we create sorted lists of just their addresses so
        # we can use them for fast, fuzzy address lookup (eg, bisect) later on.
        #
        #  c.f:
        #   - get_node(ea)
        #   - get_function(ea)
        #

        self._node_addresses     = sorted(self.nodes.keys())
        self._function_addresses = sorted(self.functions.keys())

    #--------------------------------------------------------------------------
    # Providers
    #--------------------------------------------------------------------------

    def get_node(self, address):
        """
        Get the node (basic block) for a given address.

        This function provides fast lookup of node metadata for an
        arbitrary address (ea). Assuming the address falls within a
        defined function, there should exist a graph node for it.

        We use bisection across the defined node (basic block) addresses
        to perform a fuzzy lookup of the closest node just prior to the
        target address.

        If the target address falls within the probed node, the node's
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

    #--------------------------------------------------------------------------
    # Metadata Population
    #--------------------------------------------------------------------------

    def _build_metadata(self):
        """
        Collect metadata from the underlying database.

        This function is intended to be used only once per DatabaseMetadata
        object (for now). It is responsible for collecting metadata for the
        entire database in the most performant manner possible.
        """
        assert not (self.nodes or self.functions)

        # loop through every defined function (address) in the database
        for function_address in idautils.Functions():

            # build function metadata, saving it to the database-wide function list
            self.functions[function_address] = FunctionMetadata(function_address, self)

#------------------------------------------------------------------------------
# Function Level Metadata
#------------------------------------------------------------------------------

class FunctionMetadata(object):
    """
    Fast access function level metadata cache.
    """

    def __init__(self, address, database):
        self._database = database

        # function metadata
        self.address = address
        self.name    = None

        # node metadata
        self.nodes = {}

        # fixed/baked/computed metrics
        self.size = 0
        self.node_count = 0
        self.instruction_count = 0

        # collect metdata from the underlying database
        self._build_metadata()

    #--------------------------------------------------------------------------
    # Metadata Population
    #--------------------------------------------------------------------------

    def _build_metadata(self):
        """
        Collect function metadata from the underlying database.
        """
        self._refresh_name()
        self._refresh_nodes()
        self._finalize()

    def _refresh_name(self):
        """
        Refresh the function name against the open database.
        """
        self.name = idaapi.get_func_name2(self.address)

    def _refresh_nodes(self):
        """
        Refresh the function nodes against the open database.
        """
        function_metadata, database = self, self._database

        # dispose of stale information
        function_metadata.nodes = {}

        # get function & flowchart object from database
        function  = idaapi.get_func(self.address)
        flowchart = idaapi.qflow_chart_t("", function, idaapi.BADADDR, idaapi.BADADDR, 0)

        #
        # now we will walk the flowchart for this function, collecting
        # information on each of its nodes (basic blocks) and populating
        # the function & node metadata objects.
        #

        for node_id in xrange(flowchart.size()):
            node = flowchart[node_id]

            #
            # attempt to select the node via address from our database-wide
            # node list (should the node already exist)
            #
            #   eg: a node may be shared between multiple functions
            #

            node_metadata = database.nodes.get(
                node.startEA,
                NodeMetadata(node) # create a new node
            )

            #
            # a node's id will be unique per flowchart (function). we need
            # these id's cached such that we can quickly paint nodes.
            #
            # save the node's id as it exists in *this* function into a
            # map, keyed by the function address
            #

            node_metadata.ids[self.address] = node_id

            #
            # establish a relationship between this node (basic block) and
            # this function (as one of its owners/xrefs)
            #

            node_metadata.functions[self.address] = function_metadata
            function_metadata.nodes[node.startEA] = node_metadata

            # finally, ensure the node exists in the database-wide node list
            database.nodes[node.startEA] = node_metadata

    def _finalize(self):
        """
        Finalize function metadata for use.
        """
        self.size = sum(node.size for node in self.nodes.itervalues())
        self.node_count = len(self.nodes)
        self.instruction_count = sum(node.instruction_count for node in self.nodes.itervalues())

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

        #----------------------------------------------------------------------

        # collect metdata from the underlying database
        self._build_metadata()

    #--------------------------------------------------------------------------
    # Metadata Population
    #--------------------------------------------------------------------------

    def _build_metadata(self):
        """
        Collect node metadata from the underlying database.
        """
        current_address = self.address
        node_end = self.address + self.size

        # loop through the node's entire range and count its instructions
        #   NOTE: we are assuming that every defined 'head' is an instruction
        while current_address != idaapi.BADADDR:
            self.instruction_count += 1
            current_address = idaapi.next_head(current_address, node_end)

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
