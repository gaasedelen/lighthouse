import logging

import cutter
import CutterBindings

from lighthouse.util.qt import QtGui
#from lighthouse.palette import to_rgb
from lighthouse.painting import DatabasePainter
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.Painting.Cutter")

#------------------------------------------------------------------------------
# Cutter Painter
#------------------------------------------------------------------------------

class CutterPainter(DatabasePainter):
    """
    Asynchronous Cutter database painter.
    """
    PAINTER_SLEEP = 0.01

    def __init__(self, lctx, director, palette):
        super(CutterPainter, self).__init__(lctx, director, palette)

    #--------------------------------------------------------------------------
    # Paint Primitives
    #--------------------------------------------------------------------------

    #
    # NOTE:
    #   due to the manner in which Cutter implements basic block
    #   (node) highlighting, I am not sure it is worth it to paint individual
    #   instructions. for now we, will simply make the instruction
    #   painting functions no-op's
    #

    def _paint_instructions(self, instructions):
        self._action_complete.set()

    def _clear_instructions(self, instructions):
        self._action_complete.set()

    def _paint_nodes(self, nodes_addresses):
        #b, g, r = to_rgb(self.palette.coverage_paint)
        (r, g, b, _) = self.palette.coverage_paint.getRgb()
        color = QtGui.QColor(r, g, b)

        for node_address in nodes_addresses:
            #node_metadata = self.director.metadata.nodes.get(node_address, None)
            logger.debug('Painting node at {} with {}'.format(node_address, disassembler.highlighter))
            disassembler.highlighter.highlight(self.director.coverage.nodes.get(node_address, None), color)
            self._painted_nodes.add(node_address)
        self._action_complete.set()

    def _clear_nodes(self, addresses):
        for address in addresses:
            #disassembler._core.getBBHighlighter().clear(address)
            disassembler.highlighter.clear(address)
            self._painted_nodes.discard(address)
        self._action_complete.set()

    def _refresh_ui(self):
        cutter.refresh() # TODO/CUTTER: Need a graph specific refresh...

    def _cancel_action(self, job):
        pass

    #--------------------------------------------------------------------------
    # Priority Painting
    #--------------------------------------------------------------------------

    def _priority_paint(self):
        current_address = disassembler[self.lctx].get_current_address()
        current_function = disassembler[self.lctx].get_function_at(current_address)
        if current_function:
            self._paint_function(current_function['offset'])
        return True

    def _paint_function(self, function):
        pass

