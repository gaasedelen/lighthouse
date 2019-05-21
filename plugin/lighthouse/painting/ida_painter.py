import logging
import functools

import idc
import idaapi

from lighthouse.util import *
from lighthouse.util.disassembler import disassembler
from lighthouse.util.disassembler.ida_api import map_line2citem, map_line2node, lex_citem_indexes
from lighthouse.painting import DatabasePainter

logger = logging.getLogger("Lighthouse.Painting.IDA")

#------------------------------------------------------------------------------
# MFF_NOWAIT Workaound
#------------------------------------------------------------------------------
#
#    due to the asynchronous nature of the database painter core, we need
#    to use IDA's execute_sync() with idaapi.MFF_WRITE to perform 'paint'
#    actions (which modify the database).
#
#     1. the first issue is that a deadlock can occur when attempting to use
#     execute_sync() with MFF_WRITE from a thread when IDA is in the process
#     of closing. This would occur when a paint was in progress, and the user
#     attempts to abruptly close the database.
#
#     the solution to this is to use the MFF_NOWAIT flag with MFF_WRITE, which
#     means execute_sync() is non-blocking. this avoids the deadlock that could
#     occur between the main thread and the async (painting) thread on close.
#
#     2. but prior to IDA 7.0 SP1, there was a bug with execute_sync() that
#     could cause IDA to abort() non-deterministically when using the
#     MFF_NOWAIT flag. The abort manifests as a hard-crash of IDA.
#
#    this is an issue that has haunted lighthouse since almost the beginning,
#    causing a number of compatibility/stability issues. the bug was fixed in
#    in IDA 7.0 SP1, but older versions of IDA are afflicted.
#
#    this section of code constitutes some of the most fragile, convoluted,
#    and regression prone code in lighthouse. through some miraculous feats
#    of engineering, the solution below appears to safely resolve both of
#    these problems for downlevel versions (IDA 6.8 --> 7.0)
#

from lighthouse.util.qt import QtCore

class ToMainthread(QtCore.QObject):
    """
    A Qt object whose sole purpose is to execute code on the mainthread.

    Below, we define a Qt signal called 'mainthread'. Any thread can emit() this
    signal, where it will be handled in the main application thread.
    """
    mainthread = QtCore.pyqtSignal(object)

    def __init__(self):
        super(ToMainthread, self).__init__()

        #
        # from any thread, one can call 'mainthread.emit(a_function)', passing
        # in a callable object (a_function) which will be executed (through the
        # lambda) on the main application thread.
        #

        self.mainthread.connect(lambda x: x())

def execute_paint(function):
    """
    A function decorator to safely paint the IDA database from any thread.
    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):

        #
        # the first argument passed to this decorator will be the
        # IDAPainter class instance
        #

        ida_painter = args[0]

        #
        # we wrap up the remaining args (and paint function) into a single
        # packaged up callable object (a functools.partial)
        #

        ff = functools.partial(function, *args, **kwargs)

        #
        # if we are using a 'bugged' downlevel version of IDA, package another
        # callable to 'synchronize' a database write. This callable will get
        # passed to the main thread and executed through the Qt event loop.
        #
        # the execute_sync should technically happy in-line, avoiding the
        # possibility of deadlocks or aborts as described above.
        #

        if idaapi.IDA_SDK_VERSION < 710:
            fff = functools.partial(idaapi.execute_sync, ff, idaapi.MFF_WRITE)
            ida_painter._signal.mainthread.emit(fff)
            return idaapi.BADADDR

        #
        # in IDA 7.1, the MFF_NOWAIT bug is definitely fixed, so we can just
        # use it to schedule our paint action ... as designed.
        #

        return idaapi.execute_sync(ff, idaapi.MFF_NOWAIT | idaapi.MFF_WRITE)
    return wrapper

#------------------------------------------------------------------------------
# IDA Painter
#------------------------------------------------------------------------------

class IDAPainter(DatabasePainter):
    """
    Asynchronous IDA database painter.
    """

    def __init__(self, director, palette):

        #----------------------------------------------------------------------
        # HexRays Hooking
        #----------------------------------------------------------------------

        #
        # we attempt to hook hexrays the *first* time a repaint request is
        # made. the assumption being that IDA is fully loaded and if hexrays is
        # present, it will definitely be available (for hooking) by this time
        #

        self._attempted_hook = False

        # see the MFF_NOWAIT workaround details above
        self._signal = ToMainthread()

        # continue normal painter initialization
        super(IDAPainter, self).__init__(director, palette)

    def repaint(self):
        """
        Paint coverage defined by the current database mappings.
        """

        # attempt to hook hexrays *once*
        if not self._attempted_hook:
            self._init_hexrays_hooks()
            self._attempted_hook = True

        # execute underlying repaint function
        super(IDAPainter, self).repaint()

    #------------------------------------------------------------------------------
    # Paint Actions
    #------------------------------------------------------------------------------

    #
    # NOTE:
    #   these are 'internal' functions meant only to be used by the painter.
    #   they are decorated with @execute_paint to force execution into the
    #   mainthread, where it is safe to paint (in IDA)
    #

    @execute_paint
    def _paint_instructions(self, instructions):
        self.paint_instructions(instructions)
        self._action_complete.set()

    @execute_paint
    def _clear_instructions(self, instructions):
        self.clear_instructions(instructions)
        self._action_complete.set()

    @execute_paint
    def _paint_nodes(self, nodes_coverage):
        self.paint_nodes(nodes_coverage)
        self._action_complete.set()

    @execute_paint
    def _clear_nodes(self, nodes_metadata):
        self.clear_nodes(nodes_metadata)
        self._action_complete.set()

    @execute_paint
    def _refresh_ui(self):
        """
        Note that this has been decorated with @execute_paint (vs @execute_ui)
        to help avoid deadlocking on exit.
        """
        idaapi.refresh_idaview_anyway()

    def _cancel_action(self, job_id):
        if idaapi.IDA_SDK_VERSION < 710:
            return
        idaapi.cancel_exec_request(job_id)

    #------------------------------------------------------------------------------
    # Paint Actions
    #------------------------------------------------------------------------------

    def paint_instructions(self, instructions):
        """
        Paint instruction level coverage defined by the current database mapping.
        """
        for address in instructions:
            idaapi.set_item_color(address, self.palette.coverage_paint)
        self._painted_instructions |= set(instructions)

    def clear_instructions(self, instructions):
        """
        Clear paint from the given instructions.
        """
        for address in instructions:
            idaapi.set_item_color(address, idc.DEFCOLOR)
        self._painted_instructions -= set(instructions)

    def paint_nodes(self, nodes_coverage):
        """
        Paint node level coverage defined by the current database mappings.
        """
        db_metadata = self._director.metadata

        # create a node info object as our vehicle for setting the node color
        node_info = idaapi.node_info_t()

        # NOTE/COMPAT:
        if disassembler.USING_IDA7API:
            set_node_info = idaapi.set_node_info
        else:
            set_node_info = idaapi.set_node_info2

        #
        # loop through every node that we have coverage data for, painting them
        # in the IDA graph view as applicable.
        #

        for node_coverage in nodes_coverage:
            node_metadata = db_metadata.nodes[node_coverage.address]

            # assign the background color we would like to paint to this node
            node_info.bg_color = self.palette.coverage_paint

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
        if disassembler.USING_IDA7API:
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

    #------------------------------------------------------------------------------
    # Painting - HexRays (Decompilation / Source)
    #------------------------------------------------------------------------------

    def _init_hexrays_hooks(self):
        """
        Install Hex-Rays hooks (when available).
        """
        result = False

        if idaapi.init_hexrays_plugin():
            logger.debug("HexRays present, installing hooks...")
            result = idaapi.install_hexrays_callback(self._hxe_callback)

        logger.debug("HexRays hooked: %r" % result)

    def paint_hexrays(self, cfunc, db_coverage):
        """
        Paint decompilation text for the given HexRays Window.
        """
        logger.debug("Painting HexRays for 0x%X" % cfunc.entry_ea)

        # more code-friendly, readable aliases
        db_metadata = db_coverage._metadata
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

        line2node = map_line2node(cfunc, db_metadata, line2citem)

        # great, now we have all the information we need to paint

        #
        # paint hexrays output
        #

        lines_painted = 0

        # extract the node addresses that have been hit by our function's mapping data
        executed_nodes = set(db_coverage.functions[cfunc.entry_ea].nodes.iterkeys())

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
                decompilation_text[line_number].bgcolor = self.palette.coverage_paint
                lines_painted += 1

        #
        # done painting from our mapping data
        #

        # if there was nothing painted yet, there's no point in continuing...
        if not lines_painted:
            return

        #
        # if we made it this far, we must have painted *some* lines inside the
        # function. that means we should paint the function declaration, and
        # header (variable declaration) lines as their execution will be implied
        #

        for line_number in xrange(0, cfunc.hdrlines):
            decompilation_text[line_number].bgcolor = self.palette.coverage_paint
            lines_painted += 1

        # finally, refresh the view
        self._refresh_ui()

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
        cursor_address = disassembler.execute_read(idaapi.get_screen_ea)()

        # paint functions around the cursor address
        if not self._priority_paint_functions(cursor_address):
            return False # a repaint was requested

        # paint instructions around the cursor address
        #if not self._priority_paint_instructions(cursor_address):
        #    return False # a repaint was requested

        # refresh the view
        self._refresh_ui()

        # successful completion
        return True

    def _priority_paint_functions(self, target_address):
        """
        Paint functions in the immediate vicinity of the given address.

        This will paint both the instructions & graph nodes of defined functions.
        """
        db_metadata = self._director.metadata
        db_coverage = self._director.coverage

        # the number of functions before and after the cursor to paint
        FUNCTION_BUFFER = 1

        # get the function metadata for the function closest to our cursor
        function_metadata = db_metadata.get_closest_function(target_address)
        if not function_metadata:
            return False # a repaint was requested

        # select the range of functions around us that we would like to paint
        func_num = db_metadata.get_function_index(function_metadata.address)
        func_num_start = max(func_num - FUNCTION_BUFFER, 0)
        func_num_end   = min(func_num + FUNCTION_BUFFER + 1, len(db_metadata.functions))

        # repaint the specified range of functions
        for current_num in xrange(func_num_start, func_num_end):

            # get the next function to paint
            function_metadata = db_metadata.get_function_by_index(current_num)
            if not function_metadata:
                continue
            function_address = function_metadata.address

            # get the function coverage data for the target address
            function_coverage = db_coverage.functions.get(function_address, None)

            # if there is no function coverage, clear the function
            if not function_coverage:
                if not self._clear_function(function_address):
                    return False # a repaint was requested
                continue

            # there is coverage, so repaint the function
            if not self._paint_function(function_address):
                return False # a repaint was requested

        # paint finished successfully
        return True

    def _priority_paint_instructions(self, target_address):
        """
        Paint instructions in the immediate vicinity of the given address.
        """
        db_metadata = self._director.metadata
        db_coverage = self._director.coverage

        # the number of instruction bytes before and after the cursor to paint
        INSTRUCTION_BUFFER = 200

        # determine range of instructions to repaint
        start_address = max(target_address - INSTRUCTION_BUFFER, 0)
        end_address   = target_address + INSTRUCTION_BUFFER
        instructions  = set(db_metadata.get_instructions_slice(start_address, end_address))

        # mask only the instructions with coverage data in this region
        instructions_coverage = instructions & db_coverage.coverage

        #
        # clear all instructions in this region, repaint the coverage data
        #

        # clear instructions
        if not self._async_action(self._clear_instructions, instructions):
            return False # a repaint was requested

        # paint instructions
        if not self._async_action(self._paint_instructions, instructions_coverage):
            return False # a repaint was requested

        # paint finished successfully
        return True
