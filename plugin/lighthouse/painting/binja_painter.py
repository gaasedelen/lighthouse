import logging

import binaryninja
from binaryninja import HighlightStandardColor
from binaryninja.highlight import HighlightColor

from lighthouse.painting import DatabasePainter
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.Painting.Binja")

#------------------------------------------------------------------------------
# Binary Ninja Painter
#------------------------------------------------------------------------------

class BinjaPainter(DatabasePainter):
    """
    Asynchronous Binary Ninja database painter.
    """

    def __init__(self, lctx, director, palette):
        super(BinjaPainter, self).__init__(lctx, director, palette)

    #--------------------------------------------------------------------------
    # Paint Primitives
    #--------------------------------------------------------------------------

    #
    # NOTE:
    #   due to the manner in which Binary Ninja implements basic block
    #   (node) highlighting, there is almost no need to paint individual
    #   instructions. for now we, will simply make the main instruction
    #   painting function a no-op's
    #

    def _paint_instructions(self, instructions):
        self._action_complete.set()

    def _clear_instructions(self, instructions):
        bv = disassembler[self.lctx].bv
        for address in instructions:
            for func in bv.get_functions_containing(address):
                func.set_auto_instr_highlight(address, HighlightStandardColor.NoHighlightColor)
        self._painted_partial -= set(instructions)
        self._painted_instructions -= set(instructions)
        self._action_complete.set()

    def _partial_paint(self, bv, instructions, color):
        for address in instructions:
            for func in bv.get_functions_containing(address):
                func.set_auto_instr_highlight(address, color)
        self._painted_partial |= set(instructions)
        self._painted_instructions |= set(instructions)

    def _paint_nodes(self, node_addresses):
        bv = disassembler[self.lctx].bv
        db_coverage = self.director.coverage
        db_metadata = self.director.metadata

        r, g, b, _ = self.palette.coverage_paint.getRgb()
        color = HighlightColor(red=r, green=g, blue=b)

        partial_nodes = set()
        for node_address in node_addresses:
            node_metadata = db_metadata.nodes.get(node_address, None)
            node_coverage = db_coverage.nodes.get(node_address, None)

            # read comment in ida_painter.py (self._paint_nodes)
            if not (node_coverage and node_metadata):
                self._msg_queue.put(self.MSG_ABORT)
                node_addresses = node_addresses[:node_addresses.index(node_address)]
                break

            # special case for nodes that are only partially executed...
            if node_coverage.instructions_executed != node_metadata.instruction_count:
                partial_nodes.add(node_address)
                self._partial_paint(bv, node_coverage.executed_instructions.keys(), color)
                continue

            for node in bv.get_basic_blocks_starting_at(node_address):
                node.highlight = color

        self._painted_nodes |= (set(node_addresses) - partial_nodes)
        self._action_complete.set()

    def _clear_nodes(self, node_addresses):
        bv = disassembler[self.lctx].bv
        db_metadata = self.director.metadata

        for node_address in node_addresses:
            node_metadata = db_metadata.nodes.get(node_address, None)

            # read comment in ida_painter.py (self._paint_nodes)
            if not node_metadata:
                self._msg_queue.put(self.MSG_ABORT)
                node_addresses = node_addresses[:node_addresses.index(node_address)]
                break

            for node in bv.get_basic_blocks_starting_at(node_address):
                node.highlight = HighlightStandardColor.NoHighlightColor

        self._painted_nodes -= set(node_addresses)
        self._action_complete.set()

    def _refresh_ui(self):
        pass

    def _cancel_action(self, job):
        pass

