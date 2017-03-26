import bisect
import logging

import idaapi
import idautils

from lighthouse.util import *

logger = logging.getLogger("Lighthouse.Metadata")

#------------------------------------------------------------------------------
# Metadata
#------------------------------------------------------------------------------
#
#    To aid in performance, the director lifts and indexes a limited
#    representation of the database (referred to as 'metadata' in code.)
#
#    This lifted metadata effectively eliminates what becomes otherwise
#    costly runtime communication between the director and IDA. It is also
#    tailored for efficiency and speed to complement our needs. Once built,
#    the metadata cache stands completely independent of IDA.
#
#    This opens up a realm of interesting possibilities. With this model,
#    we can easily move any heavy director based compute to asynchrnous
#    python-only threads without disrupting the user, or IDA.
#
#    However, there are two main caveats of this model -
#
#    1. The cached 'metadata' representation may not always be true to
#       state of the database. For example, if the user defines/undefines
#       functions, the metadata cache will not be aware of such changes.
#
#       Lighthouse will try to update the director's metadata cache when
#       applicable, but there are instances when it will be in the best
#       interest of the user to manually trigger a refresh of the metadata.
#
#    2. Building the metadata comes with an upfront cost, but this cost has
#       been reduced as much as possible. For example, generating metadata
#       for a database with ~17k functions, ~95k nodes (basic blocks), and
#       ~563k instructions takes only ~2.5 seconds.
#
#       This will be negligible for small-medium sized databases, but may
#       still be jarring for larger databases.
#
#    Ultimately, this model provides us responsive user experience at the
#    expense of the ocassional inaccuracies that can be corrected by a
#    reasonably low cost refresh.
#

#------------------------------------------------------------------------------
# Database Level Metadata
#------------------------------------------------------------------------------

class DatabaseMetadata(object):
    """
    Fast access database level metadata cache.
    """

    def __init__(self, populate=True):

        # database defined nodes (basic blocks)
        self.nodes = {}
        self._node_addresses = []
        self._last_node = [] # blank iterable for now

        # database defined functions
        self.functions = {}
        self._function_addresses = []

        # TODO: database defined segments
        #self.segments = {}
        #self._segment_addresses = {}

        #----------------------------------------------------------------------

        # collect metdata from the underlying database
        if populate:
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

        # fast path
        if address in self._last_node:
            return self._last_node

        # locate the index of the closest cached node address (rounding down)
        node_index = bisect.bisect_right(self._node_addresses, address) - 1

        # if the identified node contains our target address, it is a match
        try:
            node = self.nodes[self._node_addresses[node_index]]
            if address in node:
                self._last_node = node
                return node
        except (IndexError, KeyError):
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

    def __contains__(self, address):
        """
        Overload of 'in' keyword.

        Check if an address falls within a node (basic block).
        """
        if self.address <= address < self.address + self.size:
            return True
        return False

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

    #--------------------------------------------------------------------------
    # Operator Overloads
    #--------------------------------------------------------------------------

    def __eq__(self, other):
        """
        Compute node equality (==)
        """
        result = True
        result &= self.size == other.size
        result &= self.address == other.address
        result &= self.instruction_count == other.instruction_count
        result &= self.functions.viewkeys() == other.functions.viewkeys()
        result &= self.ids == other.ids
        return result

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

#------------------------------------------------------------------------------
# Metadata Helpers
#------------------------------------------------------------------------------

class MetadataDelta(object):
    """
    The computed delta between two DatabaseMetadata objects.
    """

    def __init__(self, new_metadata, old_metadata):

        # nodes
        self.nodes_added    = set()
        self.nodes_removed  = set()
        self.nodes_modified = set()

        # functions
        self.functions_added    = set()
        self.functions_removed  = set()
        self.functions_modified = set()
        self._dirty_functions   = set() # internal use only

        # compute the difference between the two metadata objects
        self._compute_delta(new_metadata, old_metadata)

    def _compute_delta(self, new_metadata, old_metadata):
        """
        Comptue the delta between two DatabaseMetadata objects.

        op1 is assumed to be the 'newer' / latest metadata, whereas op2
        is the 'older' / previous metadata.
        """
        assert isinstance(new_metadata, DatabaseMetadata)

        # accept an old_metadata of type 'None'
        if old_metadata is None:

            #
            # if the old metadata is 'None', we can assume *everything*
            # that may exist in the new_metadata must have been 'added'
            #

            self.nodes_added     = set(new_metadata.nodes.viewkeys())
            self.functions_added = set(new_metadata.functions.viewkeys())

            # nothing else to do
            return

        #
        # both new_metadata and old_metadata are real DatabaseMetadata objects
        # that we need to diff against each other, so compute their delta now
        #

        # compute the node delta
        self._compute_node_delta(new_metadata.nodes, old_metadata.nodes)

        # compute the function delta
        self._compute_function_delta(new_metadata.functions, old_metadata.functions)

        # done
        return

    def _compute_node_delta(self, new_nodes, old_nodes):
        """
        Compute the delta between two dictionaries of node metadata.
        """

        # loop through *all* the node addresses in both metadata objects
        all_node_addresses = new_nodes.viewkeys() | old_nodes.viewkeys()
        for node_address in all_node_addresses:

            # probe for this node in the metadata sets
            new_node_metadata = new_nodes.get(node_address, None)
            old_node_metadata = old_nodes.get(node_address, None)

            # the node does NOT exist in the new metadata, so it was deleted
            if not new_node_metadata:
                self.nodes_removed.add(node_address)
                self._dirty_functions |= set(old_node_metadata.functions.viewkeys())
                continue

            # the node does NOT exist in the old metadata, so it was added
            if not old_node_metadata:
                self.nodes_added.add(node_address)
                self._dirty_functions |= set(new_node_metadata.functions.viewkeys())
                continue

            #
            # ~ the node exists in *both* metadata sets ~
            #

            # if the nodes are identical, there's no delta (change)
            if new_node_metadata == old_node_metadata:
                continue

            # the nodes do not match, that's a difference!
            self.nodes_modified.add(node_address)
            self._dirty_functions |= set(new_node_metadata.functions.viewkeys())
            self._dirty_functions |= set(old_node_metadata.functions.viewkeys())

    def _compute_function_delta(self, new_functions, old_functions):
        """
        Compute the delta between two dictionaries of function metadata.
        """

        #
        # thanks to the work we did in _compute_node_delta, in theory we know
        # exactly which functions may have changed between the two metadata sets
        #
        # we loop through only these addresses, and bucketize them as needed
        #

        for function_address in self._dirty_functions:

            # probe for this function in the metadata sets
            new_func_metadata = new_functions.get(function_address, None)
            old_func_metadata = old_functions.get(function_address, None)

            # the function does NOT exist in the new metadata, so it was deleted
            if not new_func_metadata:
                self.functions_removed.add(function_address)
                continue

            # the function does NOT exist in the old metadata, so it was added
            if not old_func_metadata:
                self.functions_added.add(function_address)
                continue

            #
            # ~ the function exists in *both* metadata sets ~
            #

            #
            # in theory, every function that makes it this far given the
            # self._dirty_functions set should be different as one of its
            # underlying nodes were known to have changed...
            #

            self.functions_modified.add(function_address)

        # dispose of the dirty functions list as they're no longer needed
        self._dirty_functions = set()

    #--------------------------------------------------------------------------
    # Informational / Debug
    #--------------------------------------------------------------------------

    def dump_delta(self):
        """
        Dump the delta in human readable format.
        """
        self.dump_node_delta()
        self.dump_function_delta()

    def dump_node_delta(self):
        """
        Dump the computed node delta.
        """

        lmsg("Nodes added:")
        lmsg(hex_list(self.nodes_added))

        lmsg("Nodes removed:")
        lmsg(hex_list(self.nodes_removed))

        lmsg("Nodes modified:")
        lmsg(hex_list(self.nodes_modified))

    def dump_function_delta(self):
        """
        Dump the computed function delta.
        """

        lmsg("Functions added:")
        lmsg(hex_list(self.functions_added))

        lmsg("Functions removed:")
        lmsg(hex_list(self.functions_removed))

        lmsg("Functions modified:")
        lmsg(hex_list(self.functions_modified))
