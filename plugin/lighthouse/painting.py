import idaapi

#------------------------------------------------------------------------------
# Instructions / Items (Lines)
#------------------------------------------------------------------------------

def color_items(address, size, color):
    """
    Color a region as specified by address and size.
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
# Basic Blocks (Nodes)
#------------------------------------------------------------------------------

def color_node(address, color):
    """
    Color a basic block node by address.
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
    Color a list of basic block nodes within function at function_address.
    """

    # create node info object with specified color
    node_info = idaapi.node_info_t()
    node_info.bg_color = color

    # paint the specified nodes
    for node_id in nodes:
        idaapi.set_node_info2(
            function_address,
            node_id,
            node_info,
            idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR
        )

