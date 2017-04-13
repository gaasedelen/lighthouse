import logging

import idc
import idaapi

from lighthouse.util.ida import *

logger = logging.getLogger("Lighthouse.Painting")

#------------------------------------------------------------------------------
# Painting
#------------------------------------------------------------------------------

def paint_coverage(database_coverage, color):
    """
    Paint coverage defined by the given database mapping.
    """

    # paint individual instructions
    paint_instruction_coverage(database_coverage, color)

    # paint nodes in function graphs
    paint_node_coverage(database_coverage._metadata.nodes, database_coverage.nodes)

    # NOTE: We paint hexrays on-request

def unpaint_coverage(database_coverage):
    """
    Unpaint coverage defined by the given database mapping.
    """
    unpaint_instruction_coverage(database_coverage)
    unpaint_node_coverage(database_coverage._metadata.nodes, database_coverage.nodes)

#------------------------------------------------------------------------------
# Painting - Instructions / Items (Lines)
#------------------------------------------------------------------------------

def paint_instruction_coverage(database_coverage, color):
    """
    Paint instruction level coverage defined by the given database mapping.
    """
    for address in database_coverage.coverage:
        idaapi.set_item_color(address, color)

def unpaint_instruction_coverage(database_coverage):
    """
    Unpaint instruction level coverage defined by the given database mapping.
    """
    for address in database_coverage.coverage:
        idaapi.set_item_color(address, idc.DEFCOLOR)

#------------------------------------------------------------------------------
# Painting - Nodes (Basic Blocks)
#------------------------------------------------------------------------------

def paint_node_coverage(nodes_metadata, nodes_coverage):
    """
    Paint function graph node coverage defined by the given node mappings.
    """

    # create a node info object as our vehicle for setting the node color
    node_info = idaapi.node_info_t()

    #
    # loop through every node that we have coverage data for, painting them
    # in the IDA graph view as applicable.
    #

    for node_coverage in nodes_coverage.itervalues():
        node_metadata = nodes_metadata[node_coverage.address]

        # assign the background color we would like to paint to this node
        node_info.bg_color = node_coverage.coverage_color

        #
        # remember, nodes may technically be 'shared' between functions,
        # so we need to paint the node in every function flowchart that
        # has a reference to it.
        #

        for function_address, node_id in node_metadata.ids.iteritems():

            # do the *actual* painting of a single node instance
            idaapi.set_node_info2(
                function_address,
                node_id,
                node_info,
                idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR
            )

def unpaint_node_coverage(nodes_metadata, nodes_coverage):
    """
    Unpaint function graph node coverage defined by the given node mappings.
    """

    # create a node info object as our vehicle for resetting the node color
    node_info = idaapi.node_info_t()
    node_info.bg_color = idc.DEFCOLOR

    #
    # loop through every node that we have coverage data for, clearing
    # their paint (color) in the IDA graph view as applicable.
    #

    for node_coverage in nodes_coverage.itervalues():
        node_metadata = nodes_metadata[node_coverage.address]

        #
        # remember, nodes may technically be 'shared' between functions,
        # so we need to clear the node's paint in every function flowchart
        # that has a reference to it.
        #

        for function_address, node_id in node_metadata.ids.iteritems():

            # do the *actual* painting of a single node instance
            idaapi.set_node_info2(
                function_address,
                node_id,
                node_info,
                idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR
            )

#------------------------------------------------------------------------------
# Painting - HexRays (Decompilation / Source)
#------------------------------------------------------------------------------

def paint_hexrays(cfunc, database_metadata, database_coverage, color):
    """
    Paint decompilation text for the given HexRays Window.
    """
    decompilation_text = cfunc.get_pseudocode()

    #
    # the objective here is to paint hexrays lines that are associated with
    # our runtime data. unfortunately, there are very few API resources that
    # link decompilation line numbers to anything (eg, citems, nodes, ea, etc)
    #
    # this means that we must build our own data relationships to draw from
    #

    #
    # first, let's build a relationship between a given line of text, and the
    # citems that contribute to it. the only way to do that (as I see it) is
    # to lex citem ID's out of the decompiled output string
    #

    line2citem = map_line2citem(decompilation_text)

    #
    # now that we have some understanding of how citems contribute to each
    # line of decompiled text, we can use this information to build a
    # relationship that ties graph nodes (basic blocks) to individual lines.
    #

    line2node = map_line2node(cfunc, database_metadata, line2citem)

    # great, now we have all the information we need to paint

    #
    # paint hexrays output
    #

    lines_painted = 0

    # extract the node addresses that have been hit by our function's mapping data
    executed_nodes = set(database_coverage.functions[cfunc.entry_ea].executed_nodes.iterkeys())

    #
    # now we loop through every line_number of the decompiled text that claims
    # to have a relationship with a graph node (basic block) and check to see
    # if it contains a node our coverage has marked as executed
    #

    for line_number, line_nodes in line2node.iteritems():

        #
        # if there is any intersection of nodes on this line and the coverage
        # data's set of executed nodes, we are inclined to color it
        #

        if line_nodes & executed_nodes:
            decompilation_text[line_number].bgcolor = color
            lines_painted += 1

    #
    # done painting from our mapping data
    #

    # if there was nothing painted yet, there's no point in continuing...
    if not lines_painted:
        return

    #
    # if we made it this far, we must have painted *some* lines inside the
    # function. that means we should paint the function decleration, and
    # header (variable decleration) lines as their execution will be implied
    #

    for line_number in xrange(0, cfunc.hdrlines):
        decompilation_text[line_number].bgcolor = color
        lines_painted += 1

    # finally, refresh the view
    idaapi.refresh_idaview_anyway()

