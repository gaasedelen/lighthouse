import time
import bisect
import logging
import threading

import idc
import idaapi

from lighthouse.util import *
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
        # HexRays Hooking
        #----------------------------------------------------------------------

        #
        # we attempt to hook hexrays the *first* time a repaint request is
        # made. the assumption being that IDA is fully loaded and if hexrays is
        # present, it will definitely be available (for hooking) by this time
        #

        self._attempted_hook = False

        #----------------------------------------------------------------------
        # Async
        #----------------------------------------------------------------------

        #
        # to communicate with the asynchronous painting thread, we send a
        # a message via the thread event to signal a new paint request, and
        # use the repaint_requested bool to interrupt a running paint request.
        #

        self._action_complete = threading.Event()
        self._repaint_request = threading.Event()
        self._repaint_requested = False
        self._end_threads = False

        #
        # asynchronous database painting thread
        #

        self._painting_worker = threading.Thread(
            target=self._async_database_painter,
            name="DatabasePainter"
        )
        self._painting_worker.start()

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------

        # register for cues from the director
        self._director.coverage_switched(self.repaint)
        self._director.coverage_modified(self.repaint)

    def terminate(self):
        """
        Cleanup & terminate the painter.
        """
        self._end_threads = True
        self._repaint_requested = True
        self._repaint_request.set()
        self._painting_worker.join()

    #--------------------------------------------------------------------------
    # Initialization
    #--------------------------------------------------------------------------

    def _init_hexrays_hooks(self):
        """
        Install Hex-Rrays hooks (when available).
        """
        result = False

        if idaapi.init_hexrays_plugin():
            logger.debug("HexRays present, installing hooks...")
            result = idaapi.install_hexrays_callback(self._hxe_callback)

        logger.debug("HexRays hooked: %r" % result)

    #------------------------------------------------------------------------------
    # Painting
    #------------------------------------------------------------------------------

    def repaint(self):
        """
        Paint coverage defined by the current database mappings.
        """

        # attempt to hook hexrays *once*
        if not self._attempted_hook:
            self._init_hexrays_hooks()
            self._attempted_hook = True

        # signal the painting thread that it's time to repaint coverage
        self._repaint_requested = True
        self._repaint_request.set()

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

    @idawrite_async
    def _paint_instructions(self, instructions):
        """
        Internal routine to force called action to the main thread.
        """
        time.sleep(0) # HACK: workaround for the idapython idaapi.MFF_NOWAIT bug
        self.paint_instructions(instructions)
        self._action_complete.set()
        time.sleep(0) # HACK: workaround for the idapython idaapi.MFF_NOWAIT bug

    @idawrite_async
    def _clear_instructions(self, instructions):
        """
        Internal routine to force called action to the main thread.
        """
        time.sleep(0) # HACK: workaround for the idapython idaapi.MFF_NOWAIT bug
        self.clear_instructions(instructions)
        self._action_complete.set()
        time.sleep(0) # HACK: workaround for the idapython idaapi.MFF_NOWAIT bug

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

    @idawrite_async
    def _paint_nodes(self, nodes_coverage):
        """
        Internal routine to force called action to the main thread.
        """
        time.sleep(0) # HACK: workaround for the idapython idaapi.MFF_NOWAIT bug
        self.paint_nodes(nodes_coverage)
        self._action_complete.set()
        time.sleep(0) # HACK: workaround for the idapython idaapi.MFF_NOWAIT bug

    @idawrite_async
    def _clear_nodes(self, nodes_metadata):
        """
        Internal routine to force called action to the main thread.
        """
        time.sleep(0) # HACK: workaround for the idapython idaapi.MFF_NOWAIT bug
        self.clear_nodes(nodes_metadata)
        self._action_complete.set()
        time.sleep(0) # HACK: workaround for the idapython idaapi.MFF_NOWAIT bug

    #------------------------------------------------------------------------------
    # Painting - Functions
    #------------------------------------------------------------------------------

    def paint_function(self, address):
        """
        Paint function instructions & nodes with the current database mappings.
        """

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
    # Painting - HexRays (Decompilation / Source)
    #------------------------------------------------------------------------------

    def paint_hexrays(self, cfunc, database_coverage):
        """
        Paint decompilation text for the given HexRays Window.
        """
        logger.debug("Painting HexRays for 0x%X" % cfunc.entry_ea)

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

    def _hxe_callback(self, event, *args):
        """
        HexRays event handler.
        """

        # decompilation text generation is complete and it is about to be shown
        if event == idaapi.hxe_text_ready:

            # more code-friendly, readable aliases
            vdui = args[0]
            cfunc = vdui.cfunc

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
        """
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

        while True:

            # wait for the next external repaint request
            self._repaint_request.wait()

            # if we've been signaled to spindown the painting thread, exit now
            if self._end_threads:
                break

            # clear the repaint flag
            self._repaint_request.clear()
            self._repaint_requested = False

            # more code-friendly, readable aliases
            database_coverage = self._director.coverage
            database_metadata = self._director.metadata

            start = time.time()
            #------------------------------------------------------------------

            #
            # immediately paint the regions of the database the user is looking at
            #

            if not self._priority_paint():
                continue # a repaint was requested

            #
            # perform a more comprehensive paint
            #

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
            logger.debug("Full Paint took %s seconds" % (end - start))

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
            # reset the paint event signal so that it is ready for the next
            # paint request. it will let us know when the asynchrnous paint
            # action has completed in the IDA main thread
            #

            self._action_complete.clear()

            #
            # paint or unpaint a chunk of 'work' (nodes, or instructions) with
            # the given paint function (eg, paint_nodes, clear_instructions)
            #

            job_id = paint_action(work_chunk)
            assert job_id != -1

            #
            # wait for the asynchrnous paint event to complete or a signal that
            # we should end this thread (via end_threads)
            #

            while not (self._action_complete.wait(timeout=0.1) or self._end_threads):
                continue

            #
            # our end_threads signal/bool can only originate from the main IDA
            # thread (plugin termination). we make the assumption that no more
            # MFF_WRITE requests (eg, 'paint_action') will get processed.
            #
            # we do a best effort to cancel the in-flight job (just in case)
            # and return so we can exit the thread.
            #

            if self._end_threads:
                idaapi.cancel_exec_request(job_id)
                return False

            #
            # the operation has been interrupted by a repaint request, bail
            # immediately so that we can process the next repaint
            #

            if self._repaint_requested:
                return False

            #
            # sleep some so we don't choke the main IDA thread
            #

            time.sleep(.001)

        # operation completed successfully
        return True
