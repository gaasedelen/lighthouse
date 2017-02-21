import logging
import idaapi

from lighthouse.util.ida import *

logger = logging.getLogger("Lighthouse.Paint")

#------------------------------------------------------------------------------
# Painting
#------------------------------------------------------------------------------

def paint_coverage(coverage, color):
    """
    Paint the database using the given coverage.
    """

    # paint individual instructions
    paint_instructions(coverage.coverage_data, color)

    # paint nodes in function graphs
    paint_nodes(coverage.functions, color)

    # NOTE: We paint hexrays on-request

#------------------------------------------------------------------------------
# Painting - Instructions / Items (Lines)
#------------------------------------------------------------------------------

def paint_instructions(coverage_blocks, color):
    """
    Paint instructions using the given coverage blocks.
    """
    for address, size in coverage_blocks:
        color_items(address, size, color)

def color_items(address, size, color):
    """
    Color a region of bytes as specified by address and size.
    """

    # loop through the entire region (address -> address+size) coloring lines
    while size > 0:

        # color the current item
        idaapi.set_item_color(address, color)

        # move forward to the next item
        next_address = idaapi.next_not_tail(address)
        size -= next_address - address
        address = next_address

    # done

#------------------------------------------------------------------------------
# Painting - Nodes (Basic Blocks)
#------------------------------------------------------------------------------

def paint_nodes(functions, color):
    """
    Paint function graph nodes using the given function coverages.
    """
    for function_coverage in functions.itervalues():
        color_nodes(function_coverage.address, function_coverage.exec_nodes, color)

def color_nodes(function_address, nodes, color):
    """
    Color a list of nodes within the function graph at function_address.
    """

    # create node info object with specified color
    node_info = idaapi.node_info_t()
    node_info.bg_color = color

    # paint the specified nodes
    for node in nodes:
        idaapi.set_node_info2(
            function_address,
            node.id,
            node_info,
            idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR
        )

#------------------------------------------------------------------------------
# Painting - HexRays (Decompilation / Source)
#------------------------------------------------------------------------------

def paint_hexrays(vdui, function_coverage, color):
    """
    Paint decompilation text for the given HexRays Window.
    """
    decompilation_text = vdui.cfunc.get_pseudocode()

    #
    # the objective here is to paint hexrays lines that are associated with
    # our coverage data. unfortunately, there are very few API resources that
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

    line2node = map_line2node(vdui.cfunc, line2citem)

    # great, now we have all the information we need to paint

    #
    # paint hexrays output
    #

    lines_painted = 0

    # extract the node ids that have been hit by our function's coverage data
    coverage_indexes = set(node.id for node in function_coverage.exec_nodes)

    #
    # now we loop through every line_number of the decompiled text that claims
    # to have a relationship with a graph node (basic block) and check to see
    # if it contains a node our coverage has marked as executed
    #

    for line_number, node_indexes in line2node.iteritems():

        #
        # if there is any intersection of nodes on this line and the coverage
        # data's set of executed nodes, color it
        #

        if node_indexes & coverage_indexes:
            decompilation_text[line_number].bgcolor = color
            lines_painted += 1

    #
    # done painting from our coverage data
    #

    # if there was nothing painted yet, there's no point in continuing...
    if not lines_painted:
        return

    #
    # if we made it this far, we must have painted *some* lines inside the
    # function. that means we should paint the function decleration, and
    # header (variable decleration) lines as their execution will be implied
    #

    for line_number in xrange(0, vdui.cfunc.hdrlines):
        decompilation_text[line_number].bgcolor = color
        lines_painted += 1

    # finally, refresh the view
    idaapi.refresh_idaview_anyway()

