import time
import Queue
import logging
import binascii
import functools

import idaapi

from .qt import *
from .misc import is_mainthread
from .disassembler import using_ida7api, using_pyqt5

logger = logging.getLogger("Lighthouse.Util.IDA")

#------------------------------------------------------------------------------
# HexRays Util
#------------------------------------------------------------------------------

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
        #logger.debug("Line Text: %s" % binascii.hexlify(line_text))

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
            node = metadata.get_node(address)

            # address not mapped to a node... weird. continue to the next citem
            if not node:
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

def lex_citem_indexes(line):
    """
    Lex all ctree item indexes from a given line of text.

    -----------------------------------------------------------------------

    The HexRays decompiler output contains invisible text tokens that can
    be used to attribute spans of text to the ctree items that produced them.

    This function will simply scrape and return a list of all the these
    tokens (COLOR_ADDR) which contain item indexes into the ctree.

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

#------------------------------------------------------------------------------
# IDA Util
#------------------------------------------------------------------------------

# taken from https://github.com/gaasedelen/prefix
PREFIX_DEFAULT = "MyPrefix"
PREFIX_SEPARATOR = '%'

def prefix_function(function_address, prefix):
    """
    Prefix a function name with the given string.
    """
    original_name = get_function_name(function_address)
    new_name = str(prefix) + PREFIX_SEPARATOR + str(original_name)

    # rename the function with the newly prefixed name
    idaapi.set_name(function_address, new_name, idaapi.SN_NOWARN)

def prefix_functions(function_addresses, prefix):
    """
    Prefix a list of functions with the given string.
    """
    for function_address in function_addresses:
        prefix_function(function_address, prefix)

def clear_prefix(function_address):
    """
    Clear the prefix from a given function.
    """
    original_name = get_function_name(function_address)

    #
    # locate the last (rfind) prefix separator in the function name as
    # we will want to keep everything that comes after it
    #

    i = original_name.rfind(PREFIX_SEPARATOR)

    # if there is no prefix (separator), there is nothing to trim
    if i == -1:
        return

    # trim the prefix off the original function name and discard it
    new_name = original_name[i+1:]

    # rename the function with the prefix stripped
    idaapi.set_name(function_address, new_name, idaapi.SN_NOWARN)

def clear_prefixes(function_addresses):
    """
    Clear the prefix from a list of given functions.
    """
    for function_address in function_addresses:
        clear_prefix(function_address)

def get_function_name(function_address):
    """
    Get a function's true name.
    """

    # get the original function name from the database
    if using_ida7api:
        original_name = idaapi.get_name(function_address)
    else:
        original_name = idaapi.get_true_name(idaapi.BADADDR, function_address)

    # sanity check
    if original_name == None:
        raise ValueError("Invalid function address")

    # return the function name
    return original_name
