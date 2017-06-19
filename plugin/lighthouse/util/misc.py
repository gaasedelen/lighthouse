import os
import collections

import idaapi
from .qtshim import using_pyqt5, QtCore, QtGui, QtWidgets

#------------------------------------------------------------------------------
# Plugin Util
#------------------------------------------------------------------------------

def plugin_resource(resource_name):
    """
    Return the full path for a given plugin resource file.
    """
    return os.path.join(
        idaapi.idadir(idaapi.PLG_SUBDIR),
        "lighthouse",
        "ui",
        "resources",
        resource_name
    )

#------------------------------------------------------------------------------
# UI Util
#------------------------------------------------------------------------------

def MonospaceFont():
    """
    Convenience alias for creating a monospace Qt font object.
    """
    font = QtGui.QFont("Monospace")
    font.setStyleHint(QtGui.QFont.TypeWriter)
    return font

#------------------------------------------------------------------------------
# Python Util
#------------------------------------------------------------------------------

def chunks(l, n):
    """
    Yield successive n-sized chunks from l.

    From http://stackoverflow.com/a/312464
    """
    for i in xrange(0, len(l), n):
        yield l[i:i + n]

def hex_list(items):
    """
    Return a string of a python-like list string, with hex numbers.

    [0, 5420, 1942512] --> '[0x0, 0x152C, 0x1DA30]'
    """
    return '[{}]'.format(', '.join('0x%X' % x for x in items))

#------------------------------------------------------------------------------
# Coverage Util
#------------------------------------------------------------------------------

def coalesce_blocks(blocks):
    """
    Coalesce a list of (address, size) blocks.

    ----------------------------------------------------------------------

    Example:
        blocks = [
            (4100, 10),
            (4200, 100),
            (4300, 10),
            (4310, 20),
            (4400, 10),
        ]

    Returns:
        coalesced = [(4100, 10), (4200, 130), (4400, 10)]

    """

    # nothing to do
    if not blocks:
        return []
    elif len(blocks) == 1:
        return blocks

    # before we can operate on the blocks, we must ensure they are sorted
    blocks = sorted(blocks)

    #
    # coalesce the list of given blocks
    #

    coalesced = [blocks.pop(0)]
    while blocks:

        block_start, block_size = blocks.pop(0)

        #
        # compute the end address of the current coalescing block. if the
        # blocks do not overlap, create a new block to start coalescing from
        #

        if sum(coalesced[-1]) < block_start:
            coalesced.append((block_start, block_size))
            continue

        #
        # the blocks overlap, so update the current coalescing block
        #

        coalesced[-1] = (coalesced[-1][0], (block_start+block_size) - coalesced[-1][0])

    # return the list of coalesced blocks
    return coalesced

def rebase_blocks(base, basic_blocks):
    """
    Rebase a list of basic blocks (address, size) to the given base.
    """
    return map(lambda x: (base + x[0], x[1]), basic_blocks)

def build_hitmap(data):
    """
    Build a hitmap from the given list of address.

    A hitmap is a map of address --> number of executions.

    The list of input addresses can be any sort of runtime trace, coverage,
    or profiiling data that one would like to build a hitmap for.
    """
    output = collections.defaultdict(int)

    # if there is no input data, simply return an empty hitmap
    if not data:
        return output

    #
    # walk through the given list of given addresses and build a
    # corresponding hitmap for them
    #

    for address in data:
        output[address] += 1

    # return the hitmap
    return output
