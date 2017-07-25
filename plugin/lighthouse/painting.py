import time
import logging
import threading

import idc
import idaapi
import idautils

from lighthouse.util import chunks
from lighthouse.util.ida import *

logger = logging.getLogger("Lighthouse.Painting")

class CoveragePainter(object):
    """
    Asynchronous database painter.
    """

    def __init__(self, director, palette):

        # color palette
        self.palette = palette
        self._director = director

        #----------------------------------------------------------------------
        # Painted State
        #----------------------------------------------------------------------

        #
        # the coverage painter maintains its own internal record of what
        # instruction addresses and graph nodes it has painted.
        #

        self._painted_nodes = set()
        self._painted_instructions = set()

        #----------------------------------------------------------------------
        # Async
        #----------------------------------------------------------------------

        #
        # to communicate with the asynchronous painting thread, we send a
        # a message over the queue to kick off a new paint event, and the
        # bool to interrupt a running paint request.
        #

        self._repaint_queue = Queue.Queue()
        self._repaint_requested = False

        #
        # asynchronous database painting thread
        #

        self._painting_worker = threading.Thread(
            target=self._async_database_painter,
            name="DatabasePainter"
        )
        self._painting_worker.daemon = True
        self._painting_worker.start()

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------

        # hook hexrays on startup
        self._hooks = PainterHooks()
        self._hooks.ready_to_run = self._init_hexrays_hooks
        self._hooks.hook()

        # register for cues from the director
        self._director.coverage_switched(self.repaint)
        self._director.coverage_modified(self.repaint)

    #--------------------------------------------------------------------------
    # Initialization
    #--------------------------------------------------------------------------

    def _init_hexrays_hooks(self):
        """
        Install Hex-Rrays hooks (when available).

        NOTE: This is called when the ui_ready_to_run event fires.
        """
        result = False

        if idaapi.init_hexrays_plugin():
            logger.debug("HexRays present, installing hooks...")
            result = idaapi.install_hexrays_callback(self._hxe_callback)

        logger.debug("HexRays hooked: %r" % result)

        #
        # we only use self._hooks (UI_Hooks) to install our hexrays hooks.
        # since this 'init' function should only ever be called once, remove
        # our UI_Hooks now to clean up after ourselves.
        #

        self._hooks.unhook()

    #------------------------------------------------------------------------------
    # Painting
    #------------------------------------------------------------------------------

    @idawrite
    def repaint(self):
        """
        Paint coverage defined by the current database mappings.
        """

        # immediately paint the regions of the database the user is looking at
        self._priority_paint()

        # request a complete repaint
        self._repaint_requested = True
        self._repaint_queue.put(True)

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

    @idawrite
    def _paint_instructions(self, instructions):
        """
        Internal routine to force called action to the main thread.
        """
        self.paint_instructions(instructions)

    @idawrite
    def _clear_instructions(self, instructions):
        """
        Internal routine to force called action to the main thread.
        """
        self.clear_instructions(instructions)

    #------------------------------------------------------------------------------
    # Painting - Nodes (Basic Blocks)
    #------------------------------------------------------------------------------

    def paint_nodes(self, nodes_coverage):
        """
        Paint node level coverage defined by the current database mappings.
        """

        # create a node info object as our vehicle for setting the node color
        node_info = idaapi.node_info_t()

        # NOTE/COMPAT:
        if using_ida7api:
            set_node_info = idaapi.set_node_info
        else:
            set_node_info = idaapi.set_node_info2

        #
        # loop through every node that we have coverage data for, painting them
        # in the IDA graph view as applicable.
        #

        for node_coverage in nodes_coverage:
            node_metadata = node_coverage._database._metadata.nodes[node_coverage.address]

            # assign the background color we would like to paint to this node
            node_info.bg_color = node_coverage.coverage_color

            # do the *actual* painting of a single node instance
            set_node_info(
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

        # NOTE/COMPAT:
        if using_ida7api:
            set_node_info = idaapi.set_node_info
        else:
            set_node_info = idaapi.set_node_info2

        #
        # loop through every node that we have metadata data for, clearing
        # their paint (color) in the IDA graph view as applicable.
        #

        for node_metadata in nodes_metadata:

            # do the *actual* painting of a single node instance
            set_node_info(
                node_metadata.function.address,
                node_metadata.id,
                node_info,
                idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR
            )

            self._painted_nodes.discard(node_metadata.address)

    @idawrite
    def _paint_nodes(self, nodes_coverage):
        """
        Internal routine to force called action to the main thread.
        """
        self.paint_nodes(nodes_coverage)

    @idawrite
    def _clear_nodes(self, nodes_metadata):
        """
        Internal routine to force called action to the main thread.
        """
        self.clear_nodes(nodes_metadata)

    #------------------------------------------------------------------------------
    # Painting - Functions
    #------------------------------------------------------------------------------

    def paint_function(self, function):
        """
        Paint function instructions & nodes with the current database mappings.
        """

        # sanity check
        if not function:
            return

        # more code-friendly, readable aliases
        metadata = self._director.metadata
        coverage = self._director.coverage

        # NOTE/COMPAT:
        if using_ida7api:
            start_ea = function.start_ea
            end_ea = function.end_ea
        else:
            start_ea = function.startEA
            end_ea = function.endEA

        # collect function information
        function_metadata = metadata.functions[start_ea]
        function_coverage = coverage.functions.get(start_ea, None)

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
        logger.debug("Painting Hexrays for 0x%X" % cfunc.entry_ea)

        # more code-friendly, readable aliases
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
        logger.debug(line2citem)

        #
        # now that we have some understanding of how citems contribute to each
        # line of decompiled text, we can use this information to build a
        # relationship that ties graph nodes (basic blocks) to individual lines.
        #

        line2node = map_line2node(cfunc, database_metadata, line2citem)
        logger.debug(line2node)

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
            logger.debug("No HexRays output was painted...")
            return

        #
        # if we made it this far, we must have painted *some* lines inside the
        # function. that means we should paint the function decleration, and
        # header (variable decleration) lines as their execution will be implied
        #

        for line_number in xrange(0, cfunc.hdrlines):
            decompilation_text[line_number].bgcolor = self.palette.ida_coverage
            lines_painted += 1

        logger.debug("Done painting HexRays request...")

        # finally, refresh the view
        idaapi.refresh_idaview_anyway()

    def _hxe_callback(self, event, *args):
        """
        HexRays event handler.
        """

        # decompilation text generation is complete and it is about to be shown
        if event == idaapi.hxe_text_ready:

            # more code-friendly, readable aliases
            vdui = args[0]
            cfunc = vdui.cfunc

            logger.debug("Caught HexRays 'Text Ready' event for 0x%X" % cfunc.entry_ea)

            # if there's no coverage data for this function, there's nothing to do
            if not cfunc.entry_ea in self._director.coverage.functions:
                return 0

            # paint the decompilation text for this function
            self.paint_hexrays(cfunc, self._director.coverage)

        return 0

    #------------------------------------------------------------------------------
    # Priority Painting
    #------------------------------------------------------------------------------

    def _priority_paint(self):
        """
        Immediately repaint regions of the database visible to the user.

        TODO:

          it would be nice to loop through the address history and grab
          other database hotspots where the user has been recently.

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
            function = idaapi.getn_func(num)
            if not function:
                continue

            # repaint the function
            self.paint_function(function)

            # NOTE/COMPAT:
            if using_ida7api:
                start_ea = function.start_ea
            else:
                start_ea = function.startEA

            # get the function coverage data for the target address
            function_coverage = database_coverage.functions.get(start_ea, None)
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

    #------------------------------------------------------------------------------
    # Asynchronous Painting
    #------------------------------------------------------------------------------

    def _async_database_painter(self):
        """
        Asynchronous database painting worker loop.
        """
        logger.debug("Starting DatabasePainter thread...")

        #
        # Asynchronous Database Painting Loop
        #

        # block until a paint has been requested
        while self._repaint_queue.get():
            database_coverage = self._director.coverage
            database_metadata = self._director.metadata

            # clear the repaint flag
            self._repaint_requested = False

            start = time.time()
            #------------------------------------------------------------------

            # compute the painted instructions that will not get painted over
            stale_instructions = self._painted_instructions - database_coverage.coverage

            # compute the painted nodes that will not get painted over
            stale_nodes_ea = self._painted_nodes - database_coverage.nodes.viewkeys()
            stale_nodes = [database_metadata.nodes[ea] for ea in stale_nodes_ea]

            # clear instructions
            if not self._async_action(self._clear_instructions, stale_instructions):
                continue # a repaint was requested

            # clear nodes
            if not self._async_action(self._clear_nodes, stale_nodes):
                continue # a repaint was requested

            # paint instructions
            if not self._async_action(self._paint_instructions, database_coverage.coverage):
                continue # a repaint was requested

            # paint nodes
            if not self._async_action(self._paint_nodes, database_coverage.nodes.itervalues()):
                continue # a repaint was requested

            #------------------------------------------------------------------
            end = time.time()
            logger.debug("Paint took %s seconds" % (end - start))

        # thread exit
        logger.debug("Exiting DatabasePainter thread...")

    def _async_action(self, paint_action, work_iterable):
        """
        Split a normal paint routine into interruptable chunks.

        Internal routine for asynchrnous painting.
        """
        CHUNK_SIZE = 800 # somewhat arbitrary

        # split the given nodes into multiple paints
        for work_chunk in chunks(list(work_iterable), CHUNK_SIZE):

            #
            # paint/clear a chunk of 'work' (nodes, or instructions) with
            # the given work action (eg, paint_nodes, clear_instructions)
            #

            paint_action(work_chunk)

            # the operation has been interrupted by a repaint request
            if self._repaint_requested:
                return False

            # sleep some so we don't choke the main IDA thread
            time.sleep(.001)

        # operation completed successfully
        return True

#------------------------------------------------------------------------------
# Painter Hooks
#------------------------------------------------------------------------------

class PainterHooks(idaapi.UI_Hooks):
    """
    This is a concrete stub of IDA's UI_Hooks.
    """
    pass

