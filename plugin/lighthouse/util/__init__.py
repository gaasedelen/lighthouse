import os
import cProfile

import idaapi

from ida import *
from log import lmsg, logging_started, start_logging
from qtshim import using_pyqt5, QtCore, QtGui, QtWidgets

def MonospaceFont():
    font = QtGui.QFont("Monospace")
    font.setStyleHint(QtGui.QFont.TypeWriter)
    return font

#------------------------------------------------------------------------------
# Profiling / Testing Helpers
#------------------------------------------------------------------------------

pr = cProfile.Profile()

def profile(func):
    """
    Function profiling decorator.
    """
    def wrap(*args, **kwargs):
        global pr
        pr.enable()
        result = func(*args, **kwargs)
        pr.disable()
        pr.print_stats(sort="tottime")
        return result
    return wrap

# portable line profiler
# from: https://gist.github.com/sibelius/3920b3eb5adab482b105
try:
    from line_profiler import LineProfiler
    def line_profile(func):
        def profiled_func(*args, **kwargs):
            try:
                profiler = LineProfiler()
                profiler.add_function(func)
                profiler.enable_by_count()
                return func(*args, **kwargs)
            finally:
                profiler.print_stats()
        return profiled_func

except ImportError:
    def line_profile(func):
        def nothing(*args, **kwargs):
            return func(*args, **kwargs)
        return nothing

#from line_profiler import LineProfiler
#lpr = LineProfiler()

#import lighthouse.metadata as metadata_module
#lpr.add_module(metadata_module)
#global lpr
#lpr.enable_by_count()
#lpr.disable_by_count()
#lpr.print_stats()

#------------------------------------------------------------------------------
# Misc
#------------------------------------------------------------------------------

def hex_list(items):
    return '[{}]'.format(', '.join('0x%08X' % x for x in items))

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

def compute_color_on_gradiant(percent, color1, color2):
    """
    Compute the color specified by a percent between two colors.

    TODO: This is silly, heavy, and can be refactored.
    """

    # dump the rgb values from QColor objects
    r1, g1, b1, _ = color1.getRgb()
    r2, g2, b2, _ = color2.getRgb()

    # compute the new color across the gradiant of color1 -> color 2
    r = r1 + percent * (r2 - r1)
    g = g1 + percent * (g2 - g1)
    b = b1 + percent * (b2 - b1)

    # return the new color
    return QtGui.QColor(r,g,b)

def resource_file(filename):
    """
    Return the absolute 'resource' filepath for a given filename.
    """
    return os.path.join(idaapi.idadir("plugins"), "lighthouse", "ui", "resources", filename)

#------------------------------------------------------------------------------
# Block Utilities
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

def index_coverage(base, coverage_blocks):
    """
    TODO
    """
    output = collections.defaultdict(int)

    for address, size in coverage_blocks:
        end_address = address + size
        while address < end_address:
            output[base+address] += 1
            address += 1

    return output
