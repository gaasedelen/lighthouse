import idaapi
import logging

logger = logging.getLogger("Lighthouse.Paint")

#------------------------------------------------------------------------------
# Painting
#------------------------------------------------------------------------------

def paint_coverage(coverage, color):
    """
    Paint coverage visualizations to the database.
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
    Paint instructions based on the given coverage data.
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
# Painting - Basic Blocks (Nodes)
#------------------------------------------------------------------------------

def paint_nodes(functions, color):
    """
    Paint function graph nodes based on the given coverage data.
    """
    for func_coverage in functions.itervalues():
        color_nodes(func_coverage.address, func_coverage.exec_nodes, color)

def color_node(address, color):
    """
    Color a basic block (node) by address.
    """
    function  = idaapi.get_func(address)
    flowchart = idaapi.FlowChart(function)

    # walk the flowchart and find the associated basic block
    found_block = None
    for bb in flowchart:
        if bb.startEA <= address < bb.endEA:
            found_block = bb
            break
    else:
        raise ValueError("Cannot find node at 0x%08x" % address)

    # color the found node
    color_nodes(funcion.startEA, [found_block.id], color)

def color_nodes(function_address, nodes, color):
    """
    Color a list of basic blocks (nodes) within function at function_address.
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
    Paint decompilation output in a HexRays window.
    """
    decompilation_text = vdui.cfunc.get_pseudocode()

    # skip the parsing of variable declarations (hdrlines)
    line_start = 0 #vdui.cfunc.hdrlines
    line_end   = decompilation_text.size()

    # build a mapping of line_number -> [citem indexes]
    line_map = {}
    for line_number in xrange(line_start, line_end):
        line = decompilation_text[line_number].line
        line_map[line_number] = extract_citem_indexes(line)
        #print "[%u] -" % line_number, indexes

    # retrieve the flowchart for this function
    function  = idaapi.get_func(vdui.cfunc.entry_ea)
    flowchart = idaapi.qflow_chart_t("", function, idaapi.BADADDR, idaapi.BADADDR, 0)
    flowchart_size  = flowchart.size()
    flowchart_nodes = {}

    # cache bounds for all flowchart nodes
    for i in xrange(flowchart_size):
        node = flowchart[i]
        flowchart_nodes[i] = (node.startEA, node.endEA)

    # build a mapping of line_number -> nodes
    cached_base = 0
    line2node = {}
    for line_number, citem_indexes in line_map.iteritems():

        nodes = set()
        for index in citem_indexes:
            item = vdui.cfunc.treeitems[index]

            # get the code address of the current citem
            address = item.ea

            # walk the flowchart and find the basic block associated with this node
            for index in xrange(flowchart_size):
                node_id = (cached_base + index) % flowchart_size
                if flowchart_nodes[node_id][0] <= address < flowchart_nodes[node_id][1]:
                    break
            else:
                #logger.warning("Failed to map node to basic block")
                continue

            # add the found basic block id
            nodes.add(node_id)
            cached_base = node_id

        # save the list of node ids identified for this decompiled line
        line2node[line_number] = nodes

    # extract the tainted coverage node ids from our coverage data
    coverage_indexes = set(node.id for node in function_coverage.exec_nodes)

    # now color any decompiled line that holds a tainted node
    lines_painted = 0
    for line_number, node_indexes in line2node.iteritems():
        try:
            if node_indexes & coverage_indexes:
                decompilation_text[line_number].bgcolor = color
                lines_painted += 1
        except KeyError as e:
            pass

    # there was nothing painted yet, there's no point in continuing
    if not lines_painted:
        return

    # paint the function decleration, and header (variable decleration) lines
    # as their execution is implied at this point
    for line_number in xrange(0, vdui.cfunc.hdrlines):
        decompilation_text[line_number].bgcolor = color
        lines_painted += 1

    # refresh the view
    idaapi.refresh_idaview_anyway()

def extract_citem_indexes(line):
    """
    Lex all ctree item indexes from a given line of text.
    """
    indexes = []

    # lex COLOR_ADDR tokens from the line
    i = 0
    while i < len(line):

        # does this character mark the start of a new COLOR_* token?
        if line[i] == idaapi.COLOR_ON:

            # move past the COLOR_ON byte
            i += 1

            # is this sequence a COLOR_ADDR token?
            if ord(line[i]) == idaapi.COLOR_ADDR:

                # move past the COLOR_ADDR byte
                i += 1

                #
                # A COLOR_ADDR token is followed by either 8, or 16 characters
                # (a hex encoded number) that in this context will be the index
                # number of a citem
                #

                citem_index = int(line[i:i+idaapi.COLOR_ADDR_SIZE], 16)
                i += idaapi.COLOR_ADDR_SIZE

                # save the extracted index
                indexes.append(citem_index)

                # skip to the next iteration as i has moved
                continue

        # nothing we care about happened, keep lexing forward
        i += 1

    # return all the citem indexes extracted from this line of text
    return indexes
