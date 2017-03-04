import cProfile
import logging
import collections

import idaapi

logger = logging.getLogger("Lighthouse.Util.IDA")

#------------------------------------------------------------------------------
# FlowChart Helpers
#------------------------------------------------------------------------------
#
#    Profiling revealed that working with flowcharts was creating the most
#    expensive set of operations for Lighthouse. Specifically:
#
#     * Creating/requesting a flowchart from IDA
#     * Repeatedly walking a flowchart from its base indexe (for our purposes)
#     * idaapi.FlowChart & BasicBlock come with their own unecessary overhead
#
#    To try to make our flowchart operations as fast as possible throughout
#    Lighthouse, we do our best to minimize the above three cases with the
#    strategies outlined below.
#
#     * Cache the last N flowcharts requested in an LRU cache implementation
#     * Cache & reuse the last node index used for a given flowchart
#     * Use qflow_chart_t directly to remove FlowChart & BasicBlock overhead
#

class FlowChartCache(object):
    """
    A LRU cache implementation for IDA FlowChart lookup.

    TODO: describe how & why the cache works
    """

    def __init__(self, capacity=6):
        self.cache = collections.deque([], capacity)

    def get(self, address):
        """
        Cached lookup of the flowchart for a given address.

        On cache-miss, a new flowchart is generated.
        """

        # cache hit
        for cache_entry in self.cache:
            bounds = cache_entry[0].bounds
            if bounds.startEA <= address < bounds.endEA:
                #logger.debug("0x%08X: cache hit!" % address)
                return cache_entry

        #
        # flow chart is NOT in the cache...
        #

        #logger.debug("0x%08X: cache miss!" % address)

        # create a new flowchart corresponding to the address
        function  = idaapi.get_func(address)
        flowchart = idaapi.qflow_chart_t("", function, idaapi.BADADDR, idaapi.BADADDR, 0)

        # cache the newly created flowchart
        cache_entry = (flowchart, 0)
        self.set(cache_entry)

        # return the created flowchart entry
        return cache_entry

    def set(self, cache_entry):
        """
        Update the cache with the given entry.
        """
        function_address = cache_entry[0].bounds.startEA

        # evict an old entry if it exists
        for i in xrange(len(self.cache)):
            if self.cache[i][0].bounds.startEA == function_address:
                del self.cache[i]
                break

        # put this new cache entry at the front of the list
        self.cache.appendleft(cache_entry)

def map_flowchart(function_address):
    """
    Map a FlowChart and its node bounds for fast access.

    -----------------------------------------------------------------------

    Walking the IDAPython flowcharts can actually be really slow. when we
    need to repeatedly access or walk a given flowchart, we should instead
    extract its layout one-time and use this minimal form when applicable.

    -----------------------------------------------------------------------

    Output:

        +- flowchart_nodes:
        |    a map keyed with node ID's, holding a tuple of node bounds
        |
        |      eg: { int(node_id): (startEA, endEA), ... }
        '

    """
    flowchart_nodes = {}

    # retrieve the flowchart for this function
    function  = idaapi.get_func(function_address)
    flowchart = idaapi.qflow_chart_t("", function, idaapi.BADADDR, idaapi.BADADDR, 0)

    # cache the bounds for every node in this flowchart
    for i in xrange(flowchart.size()):
        node = flowchart[i]
        flowchart_nodes[i] = (node.startEA, node.endEA)

    return flowchart_nodes

#------------------------------------------------------------------------------
# HexRays Helpers
#------------------------------------------------------------------------------

def lex_citem_indexes(line):
    """
    Lex all ctree item indexes from a given line of text.
    """
    i = 0
    indexes = []
    line_length = len(line)

    # lex COLOR_ADDR tokens from the line of text
    while i < line_length:

        # does this character mark the start of a new COLOR_* token?
        if line[i] == idaapi.COLOR_ON:

            # yes, so move past the COLOR_ON byte
            i += 1

            # is this sequence for a COLOR_ADDR?
            if ord(line[i]) == idaapi.COLOR_ADDR:

                # yes, so move past the COLOR_ADDR byte
                i += 1

                #
                # A COLOR_ADDR token is followed by either 8, or 16 characters
                # (a hex encoded number) that represents an address/pointer.
                # in this context, it is actually the index number of a citem
                #

                citem_index = int(line[i:i+idaapi.COLOR_ADDR_SIZE], 16)
                i += idaapi.COLOR_ADDR_SIZE

                # save the extracted citem index
                indexes.append(citem_index)

                # skip to the next iteration as i has moved
                continue

        # nothing we care about happened, keep lexing forward
        i += 1

    # return all the citem indexes extracted from this line of text
    return indexes

def map_line2citem(decompilation_text):
    """
    Map decompilation line numbers to citems.

    -----------------------------------------------------------------------

    This function allows us to build a relationship between citems in the
    ctree and specific lines in the hexrays decompilation text.

    -----------------------------------------------------------------------

    Output:

        +- line2citem:
        |    a map keyed with line numbers, holding sets of citem indexes
        |
        |      eg: { int(line_number): sets(citem_indexes), ... }
        '

    """
    line2citem = {}

    #
    # it turns out that citem indexes are actually stored inline with the
    # decompilation text output, hidden behind COLOR_ADDR tokens.
    #
    # here we pass each line of raw decompilation text to our crappy lexer,
    # extracting any COLOR_ADDR tokens as citem indexes
    #

    for line_number in xrange(decompilation_text.size()):
        line_text = decompilation_text[line_number].line
        line2citem[line_number] = lex_citem_indexes(line_text)

    return line2citem

def map_line2node(cfunc, metadata, line2citem):
    """
    Map decompilation line numbers to node (basic blocks) addresses.

    -----------------------------------------------------------------------

    This function allows us to build a relationship between graph nodes
    (basic blocks) and specific lines in the hexrays decompilation text.

    -----------------------------------------------------------------------

    Output:

        +- line2node:
        |    a map keyed with line numbers, holding sets of node addresses
        |
        |      eg: { int(line_number): set(nodes), ... }
        '

    """
    line2node = {}
    treeitems = cfunc.treeitems
    function_address = cfunc.entry_ea

    #
    # prior to this function, a line2citem map was built to tell us which
    # citems reside on any given line of text in the decompilation output.
    #
    # now, we walk through this line2citem map one 'line_number' at a time in
    # an effort to resolve the set of graph nodes associated with its citems.
    #

    for line_number, citem_indexes in line2citem.iteritems():
        nodes = set()

        #
        # we are at the level of a single line (line_number). we now consume
        # its set of citems (citem_indexes) and attempt to identify the explict
        # graph nodes they claim to be sourced from (by their reported EA)
        #

        for index in citem_indexes:

            # get the code address of the given citem
            item = treeitems[index]
            address = item.ea

            # find the graph node (eg, basic block) that generated this citem
            try:
                node = metadata.get_node(address)

            # address not mapped to a node... weird. continue to the next citem
            except ValueError:
                #logger.warning("Failed to map node to basic block")
                continue

            #
            # we made it this far, so we must have found a node that contains
            # this citem. save the computed node_id to the list of of known
            # nodes we have associated with this line of text
            #

            nodes.add(node.address)

        #
        # finally, save the completed list of node ids as identified for this
        # line of decompilation text to the line2node map that we are building
        #

        line2node[line_number] = nodes

    # all done, return the computed map
    return line2node

