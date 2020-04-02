import logging

import cutter

from lighthouse.util.qt import QtGui
from lighthouse.palette import to_rgb
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

    def __init__(self, director, palette):
        super(CutterPainter, self).__init__(director, palette)

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

    def _paint_nodes(self, nodes_coverage):
        b, g, r = to_rgb(self.palette.coverage_paint)
        color = QtGui.QColor(r, g, b)
        for node_coverage in nodes_coverage:
            node_metadata = node_coverage.database._metadata.nodes[node_coverage.address]
            disassembler._core.getBBHighlighter().highlight(node_coverage.address, color)
            self._painted_nodes.add(node_metadata.address)
        self._action_complete.set()

    def _clear_nodes(self, nodes_metadata):
        for node_metadata in nodes_metadata:
            disassembler._core.getBBHighlighter().clear(node_metadata.address)
            self._painted_nodes.discard(node_metadata.address)
        self._action_complete.set()

    def _refresh_ui(self):
        cutter.refresh() # TODO/CUTTER: Need a graph specific refresh...

    def _cancel_action(self, job):
        pass

    #--------------------------------------------------------------------------
    # Priority Painting
    #--------------------------------------------------------------------------

    def _priority_paint(self):
        current_address = disassembler.get_current_address()
        current_function = disassembler.get_function_at(current_address)
        if current_function:
            self._paint_function(current_function['offset'])
        return True

