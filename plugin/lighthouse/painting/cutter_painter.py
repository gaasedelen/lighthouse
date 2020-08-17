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

    def _partial_paint(self, addresses, color):
        try:
            highlighter = disassembler[self.lctx]._core.getBIHighlighter()
            for address in addresses:
                logger.debug('Partially painting {}'.format(address))
                highlighter.highlight(address, color)
        except Exception as e:
            logger.debug('Exception in partial paint: {}'.format(e))


    def _paint_nodes(self, nodes_addresses):
        (r, g, b, _) = self.palette.coverage_paint.getRgb()
        color = QtGui.QColor(r, g, b)
        color_partial = QtGui.QColor(r, 0, 0)

        for node_address in nodes_addresses:
            node_metadata = self.director.metadata.nodes.get(node_address, None)
            node_coverage = self.director.coverage.nodes.get(node_address, None)


            # Database unsync. Abort
            if not (node_coverage and node_metadata):
                logger.warning('Unsynced database. Aborting')
                self._msg_queue.put(self.MSG_ABORT)
                node_addresses = node_addresses[:node_addresses.index(node_address)]
                break

            # Node completely executed
            if node_coverage.instructions_executed == node_metadata.instruction_count:
                logger.debug('Painting node {}'.format(node_address))
                disassembler[self.lctx]._core.getBBHighlighter().highlight(node_address, color)
                self._painted_nodes.add(node_address)

            # Partially executed nodes
            else:
                logger.debug('Partial block {}'.format(node_address))
                self._partial_paint(node_coverage.executed_instructions.keys(), color)

        self._action_complete.set()

    def _clear_nodes(self, addresses):
        for address in addresses:
            disassembler[self.lctx]._core.getBBHighlighter().clear(address)
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

