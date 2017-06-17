import time
import logging

import idc
import idaapi
import idautils

from lighthouse.util.ida import *

logger = logging.getLogger("Lighthouse.Painting")


class CoveragePainter(object):
    """
    TODO
    """

    def __init__(self, director, palette):
        self.palette = palette
        self._director = director
        self._painted_nodes = set()
        self._painted_instructions = set()

        # register for cues from the director
        self._director.coverage_switched(self.repaint)
        self._director.coverage_modified(self.repaint)

    #------------------------------------------------------------------------------
    # Painting
    #------------------------------------------------------------------------------

    def repaint(self):
        """
        Paint coverage defined by the current database mappings
        """
        self._priority_paint()

    #------------------------------------------------------------------------------
    # Painting - Instructions / Items (Lines)
    #------------------------------------------------------------------------------

    def paint_instructions(self, instructions):
        """
        Paint instruction level coverage defined by the current database mapping.
        """
        for address in instructions:
            idaapi.set_item_color(address, self.palette.ida_coverage)
            self._painted_instructions.add(address)

    def clear_instructions(self, instructions):
        """
        Clear paint from the given instructions.
        """
        for address in instructions:
            idaapi.set_item_color(address, idc.DEFCOLOR)
            self._painted_instructions.discard(address)

    #------------------------------------------------------------------------------
    # Painting - Nodes (Basic Blocks)
    #------------------------------------------------------------------------------

    def paint_nodes(self, nodes_coverage):
        """
        Paint node level coverage defined by the current database mappings.
        """

        # create a node info object as our vehicle for setting the node color
        node_info = idaapi.node_info_t()

        #
        # loop through every node that we have coverage data for, painting them
        # in the IDA graph view as applicable.
        #

        for node_coverage in nodes_coverage:
            node_metadata = node_coverage._database._metadata.nodes[node_coverage.address]

            # assign the background color we would like to paint to this node
            node_info.bg_color = node_coverage.coverage_color

            # do the *actual* painting of a single node instance
            idaapi.set_node_info2(
                node_metadata.function.address,
                node_metadata.id,
                node_info,
                idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR
            )

            self._painted_nodes.add(node_metadata.address)

    def clear_nodes(self, nodes_metadata):
        """
        Clear paint from the given graph nodes.
        """

        # create a node info object as our vehicle for resetting the node color
        node_info = idaapi.node_info_t()
        node_info.bg_color = idc.DEFCOLOR

        #
        # loop through every node that we have metadata data for, clearing
        # their paint (color) in the IDA graph view as applicable.
        #

        for node_metadata in nodes_metadata:

            # do the *actual* painting of a single node instance
            idaapi.set_node_info2(
                node_metadata.function.address,
                node_metadata.id,
                node_info,
                idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR
            )

            self._painted_nodes.discard(node_metadata.address)

    #------------------------------------------------------------------------------
    # Painting - Functions
    #------------------------------------------------------------------------------

    def paint_function(self, function):
        """
        Paint function instructions & nodes with the current database mappings
        """

        # sanity check
        if not function:
            return

        # more code-friendly, readable aliases
        metadata = self._director.metadata
        coverage = self._director.coverage

        # collect function information
        function_metadata = metadata.functions[function.startEA]
        function_coverage = coverage.functions.get(function.startEA, None)

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

            # clear the instructions that will not get painted over
            self.clear_instructions(stale_instructions)
            self.paint_instructions(function_coverage.instructions)

            # clear the nodes that will not get painted over
            self.clear_nodes(stale_nodes)
            self.paint_nodes(function_coverage.nodes.itervalues())

        # no coverage, just clear the function's instruction & nodes
        else:
            self.clear_instructions(function_metadata.instructions)
            self.clear_nodes(function_metadata.nodes.itervalues())

    #------------------------------------------------------------------------------
    # Painting - HexRays (Decompilation / Source)
    #------------------------------------------------------------------------------

    def paint_hexrays(self, cfunc, database_coverage):
        """
        Paint decompilation text for the given HexRays Window.
        """
        database_metadata = database_coverage._metadata
        decompilation_text = cfunc.get_pseudocode()

        #
        # the objective here is to paint hexrays lines that are associated with
        # our runtime data. unfortunately, there are very few API resources that
        # link decompilation line numbers to anything (eg, citems, nodes, ea, etc)
        #
        # this means that we must build our own data relationships to draw from
        #

        #
        # first, let's build a relationship between a given line of text, and the
        # citems that contribute to it. the only way to do that (as I see it) is
        # to lex citem ID's out of the decompiled output string
        #

        line2citem = map_line2citem(decompilation_text)

        #
        # now that we have some understanding of how citems contribute to each
        # line of decompiled text, we can use this information to build a
        # relationship that ties graph nodes (basic blocks) to individual lines.
        #

        line2node = map_line2node(cfunc, database_metadata, line2citem)

        # great, now we have all the information we need to paint

        #
        # paint hexrays output
        #

        lines_painted = 0

        # extract the node addresses that have been hit by our function's mapping data
        executed_nodes = set(database_coverage.functions[cfunc.entry_ea].nodes.iterkeys())

        #
        # now we loop through every line_number of the decompiled text that claims
        # to have a relationship with a graph node (basic block) and check to see
        # if it contains a node our coverage has marked as executed
        #

        for line_number, line_nodes in line2node.iteritems():

            #
            # if there is any intersection of nodes on this line and the coverage
            # data's set of executed nodes, we are inclined to color it
            #

            if line_nodes & executed_nodes:
                decompilation_text[line_number].bgcolor = self.palette.ida_coverage
                lines_painted += 1

        #
        # done painting from our mapping data
        #

        # if there was nothing painted yet, there's no point in continuing...
        if not lines_painted:
            return

        #
        # if we made it this far, we must have painted *some* lines inside the
        # function. that means we should paint the function decleration, and
        # header (variable decleration) lines as their execution will be implied
        #

        for line_number in xrange(0, cfunc.hdrlines):
            decompilation_text[line_number].bgcolor = self.palette.ida_coverage
            lines_painted += 1

        # finally, refresh the view
        idaapi.refresh_idaview_anyway()

    #------------------------------------------------------------------------------
    # Priority Painting
    #------------------------------------------------------------------------------

    def _priority_paint(self):
        """
        Immediately repaint regions of the database visible to the user.
        """
        cursor_address = idaapi.get_screen_ea()

        # paint functions around the cursor address
        painted = self._priority_paint_functions(cursor_address)

        # paint instructions around the cursor address
        self._priority_paint_instructions(cursor_address, ignore=painted)

    def _priority_paint_functions(self, target_address):
        """
        Paint functions in the immediate vicinity of the given address.

        This will paint both the instructions & graph nodes of defined functions.
        """
        database_coverage = self._director.coverage

        # the number of functions before and after the cursor to paint
        FUNCTION_BUFFER = 1

        # determine range of functions to repaint
        func_num = idaapi.get_func_num(target_address)
        func_num_start = func_num - FUNCTION_BUFFER
        func_num_end   = func_num + FUNCTION_BUFFER + 1

        # we will save the instruction addresses painted by our function paints
        function_instructions = set()

        # repaint the specified range of functions
        for num in xrange(func_num_start, func_num_end):
            func = idaapi.getn_func(num)
            if not func:
                continue

            # repaint the function
            self.paint_function(func)

            # get the function coverage data for the target address
            function_coverage = database_coverage.functions.get(func.startEA, None)
            if not function_coverage:
                continue

            # extract the painted instructions in this function
            function_instructions |= function_coverage.instructions

        # return the instruction addresses painted
        return function_instructions

    def _priority_paint_instructions(self, target_address, ignore=set()):
        """
        Paint instructions in the immediate vicinity of the given address.

        Optionally, one can provide a set of addresses to ignore while painting.
        """
        database_coverage = self._director.coverage

        # the number of instruction bytes before and after the cursor to paint
        INSTRUCTION_BUFFER = 200

        # determine range of instructions to repaint
        inst_start = target_address - INSTRUCTION_BUFFER
        inst_end   = target_address + INSTRUCTION_BUFFER
        instructions = set(idautils.Heads(inst_start, inst_end))

        # remove any instructions painted by the function paints
        instructions -= ignore

        # mask only the instructions with coverage data in this region
        instructions_coverage = instructions & database_coverage.coverage

        # clear all instructions in this region, repaint the coverage data
        self.clear_instructions(instructions)
        self.paint_instructions(instructions_coverage)

        # return the instruction addresses painted
        return instructions_coverage

#----------------------------------------------------------------------
# Painting / TODO: move/remove?
#----------------------------------------------------------------------

def unpaint_difference(self, old_mapping, new_mapping):
    return
    logger.debug("Clearing paint difference between coverages")

    # compute the difference in coverage between two sets of mappings
    difference_mask = old_mapping.coverage - new_mapping.coverage

    # build a mapping of the computed difference
    difference = old_mapping.mask_data(difference_mask)
    difference.update_metadata(self.metadata)
    difference.refresh_nodes()

    # clear the paint on the computed difference
    unpaint_coverage(difference)

