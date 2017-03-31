import logging
import collections

import idaapi

logger = logging.getLogger("Lighthouse.Util.IDA")

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
            try:
                item = treeitems[index]
                address = item.ea

            # apparently this is a thing on IDA 6.95
            except IndexError as e:
                continue

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

#------------------------------------------------------------------------------
# Misc
#------------------------------------------------------------------------------

def get_disas_bg_color():
    """
    Get the background color of the disas text area via pixel... YOLO

    PS: please expose the get_graph_color(...) palette accessor, Ilfak ;_;
    """

    # find a form (eg, IDA view) to steal a pixel from
    for i in xrange(5):
        form = idaapi.find_tform("IDA View-%c" % chr(ord('A') + i))
        if form:
            break
    else:
        raise RuntimeError("Failed to find donor IDA View")

    # lookup the Qt Widget for the given form and take 2px tall image
    if using_pyqt5():
        widget = idaapi.PluginForm.FormToPyQtWidget(form)
        pixmap = widget.grab(QtCore.QRect(0, 0, widget.width(),2))
    else:
        widget = idaapi.PluginForm.FormToPySideWidget(form)
        pixmap = QtGui.QPixmap.grabWidget(widget, QtCore.QRect(0, 0, widget.width(), 2))

    # extract a pixel from the top center like a pleb (hopefully a background pixel :|)
    img    = QtGui.QImage(pixmap.toImage())
    color  = QtGui.QColor(img.pixel(img.width()/2,1))

    # return the color of the pixel we extracted
    return color
