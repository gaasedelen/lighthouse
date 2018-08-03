import logging

from binaryninja import HighlightStandardColor

from lighthouse.util.disassembler import *
from lighthouse.painting import DatabasePainter

logger = logging.getLogger("Lighthouse.Painting")

class BinjaPainter(DatabasePainter):
    """
    Asynchronous Binary Ninja database painter.
    """

    def __init__(self, director, palette):
        super(BinjaPainter, self).__init__(director, palette)

    #------------------------------------------------------------------------------
    # Paint Actions
    #------------------------------------------------------------------------------

    # TODO: these technicallly need to be called in a background task I think ...

    def _paint_instructions(self, instructions):
        """
        Paint instruction level coverage defined by the current database mapping.

        Internal routine to force called action to the main thread.
        """
        bv = binja_get_bv()
        for address in instructions:
            funcs = bv.get_functions_containing(address)
            if len(funcs) != 1:
                logger.warning("Painting may be incorrect (abnormal # funcs)")
                logger.warning(funcs)
            # TODO:  self.palette.ida_coverage
            funcs[0].set_auto_instr_highlight(address, HighlightStandardColor.BlueHighlightColor)
            self._painted_instructions.add(address)
        self._action_complete.set()

    def _clear_instructions(self, instructions):
        """
        Clear paint from the given instructions.

        Internal routine to force called action to the main thread.
        """
        bv = binja_get_bv()
        for address in instructions:
            funcs = bv.get_functions_containing(address)
            if len(funcs) != 1:
                logger.warning("Clearing may be incorrect (abnormal # funcs)")
                logger.warning(funcs)
            funcs[0].set_auto_instr_highlight(address, HighlightStandardColor.NoHighlightColor)
            self._painted_instructions.add(address)
        self._action_complete.set()

    def _paint_nodes(self, nodes_coverage):
        """
        Paint node level coverage defined by the current database mappings.

        Internal routine to force called action to the main thread.
        """
        bv = binja_get_bv()
        color = HighlightStandardColor.BlueHighlightColor
        for node_coverage in nodes_coverage:
            node_metadata = node_coverage._database._metadata.nodes[node_coverage.address]

            # TODO: change to containing??
            nodes = bv.get_basic_blocks_starting_at(node_metadata.address)
            for node in nodes:
                node.highlight = color

            self._painted_nodes.add(node_metadata.address)
        self._action_complete.set()

    def _clear_nodes(self, nodes_metadata):
        """
        Clear paint from the given graph nodes.

        Internal routine to force called action to the main thread.
        """
        bv = binja_get_bv()
        color = HighlightStandardColor.NoHighlightColor
        for node_coverage in nodes_coverage:
            node_metadata = node_coverage._database._metadata.nodes[node_coverage.address]

            # TODO: change to containing??
            nodes = bv.get_basic_blocks_starting_at(node_metadata.address)
            for node in nodes:
                node.highlight = color

            self._painted_nodes.discard(node_metadata.address)
        self._action_complete.set()

    def _cancel_job(self, job):
        pass # TODO
        #job.cancel()

    #------------------------------------------------------------------------------
    # Painting - Functions
    #------------------------------------------------------------------------------

    def _paint_function(self, address):
        """
        Paint function instructions & nodes with the current database mappings.
        """
        return # TODO

        # collect function information
        function_metadata = self._director.metadata.functions[address]
        function_coverage = self._director.coverage.functions.get(address, None)

        # function coverage exists, so let's do a cleaner paint
        if function_coverage:

            #
            # ~ instructions ~
            #

            # compute the painted instructions within this function
            painted = self._painted_instructions & function_metadata.instructions

            # compute the painted instructions that will not get painted over
            stale_instructions = painted - function_coverage.instructions

            #
            # ~ nodes ~
            #

            # compute the painted nodes within this function
            painted = self._painted_nodes & function_metadata.nodes.viewkeys()

            # compute the painted nodes that will not get painted over
            stale_nodes_ea = painted - function_coverage.nodes.viewkeys()
            stale_nodes = [function_metadata.nodes[ea] for ea in stale_nodes_ea]

            #
            # ~ painting ~
            #

            # clear instructions
            if not self._async_action(self._clear_instructions, stale_instructions):
                return False

            # clear nodes
            if not self._async_action(self._clear_nodes, stale_nodes):
                return False

            # paint instructions
            if not self._async_action(self._paint_instructions, function_coverage.instructions):
                return False

            # paint nodes
            if not self._async_action(self._paint_nodes, function_coverage.nodes.itervalues()):
                return False

        # no coverage, just clear the function's instruction & nodes
        else:

            # clear instructions
            if not self._async_action(self._clear_instructions, function_metadata.instructions):
                return False

            # clear nodes
            if not self._async_action(self._clear_nodes, function_metadata.nodes.itervalues()):
                return False

        # not interrupted
        return True

    #------------------------------------------------------------------------------
    # Priority Painting
    #------------------------------------------------------------------------------

    def _priority_paint(self):
        """
        Immediately repaint regions of the database visible to the user.
        """
        return True # TODO

        cursor_address = idaapi.get_screen_ea() # TODO: threadsafe?

        # paint functions around the cursor address
        painted = self._priority_paint_functions(cursor_address)

        # the operation has been interrupted by a repaint request
        if self._repaint_requested:
            return False

        # paint instructions around the cursor address
        self._priority_paint_instructions(cursor_address, ignore=painted)

        # the operation has been interrupted by a repaint request
        if self._repaint_requested:
            return False

        # succesful completion
        return True

    def _priority_paint_functions(self, target_address):
        """
        Paint functions in the immediate vicinity of the given address.

        This will paint both the instructions & graph nodes of defined functions.
        """
        database_metadata = self._director.metadata
        database_coverage = self._director.coverage
        function_instructions = set()

        # the number of functions before and after the cursor to paint
        FUNCTION_BUFFER = 1

        # get the function metadata for the function closest to our cursor
        function_metadata = database_metadata.get_closest_function(target_address)
        if not function_metadata:
            return function_instructions # this will be empty

        # select the range of functions around us that we would like to paint
        func_num = database_metadata.get_function_num(function_metadata.address)
        func_num_start = max(func_num - FUNCTION_BUFFER, 0)
        func_num_end   = func_num + FUNCTION_BUFFER + 1

        # repaint the specified range of functions
        for current_num in xrange(func_num_start, func_num_end):

            # get the next function to paint
            try:
                function_metadata = database_metadata.get_function_by_num(current_num)
            except IndexError:
                continue

            # repaint the function
            if not self.paint_function(function_metadata.address):
                break # paint interrupted

            # get the function coverage data for the target address
            function_coverage = database_coverage.functions.get(function_metadata.address, None)
            if not function_coverage:
                continue

            # accumulate the painted instructions by this pass
            function_instructions |= function_coverage.instructions

            # the operation has been interrupted by a repaint request
            if self._repaint_requested:
                break

        # return the addresses of all the instruction we painted over
        return function_instructions

    def _priority_paint_instructions(self, target_address, ignore=set()):
        """
        Paint instructions in the immediate vicinity of the given address.

        Optionally, one can provide a set of addresses to ignore while painting.
        """
        database_metadata = self._director.metadata
        database_coverage = self._director.coverage

        # the number of instruction bytes before and after the cursor to paint
        INSTRUCTION_BUFFER = 200

        # determine range of instructions to repaint
        start_address = max(target_address - INSTRUCTION_BUFFER, 0)
        end_address   = target_address + INSTRUCTION_BUFFER
        instructions  = set(database_metadata.get_instructions_slice(start_address, end_address))

        # remove any instructions painted by the function paints
        instructions -= ignore

        # mask only the instructions with coverage data in this region
        instructions_coverage = instructions & database_coverage.coverage

        #
        # clear all instructions in this region, repaint the coverage data
        #

        # clear instructions
        if not self._async_action(self._clear_instructions, instructions):
            return set()

        # paint instructions
        if not self._async_action(self._paint_instructions, instructions_coverage):
            return set()

        # return the instruction addresses painted
        return instructions_coverage
