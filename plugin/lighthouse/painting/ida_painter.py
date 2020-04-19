import struct
import ctypes
import logging
import functools

import idc
import idaapi
from idaapi import clr_abits, set_abits, netnode, set_node_info

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
#    these problems for downlevel versions (IDA 6.8 --> 7.x)
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

    def __init__(self, lctx, director, palette):
        super(IDAPainter, self).__init__(lctx, director, palette)
        self._streaming_instructions = True
        self._idp_hooks = InstructionPaintHooks(director, palette)
        self._vduis = {}

        # see the MFF_NOWAIT workaround details above
        self._signal = ToMainthread()

    def terminate(self):

        #
        # IDA is either closing or simply switching databases... we should try
        # to unhook our processor hooks so that artifacts of this painter do
        # not carry over to the next IDB / session.
        #
        # if we don't do this, our current 'IDP' hooks will continue to fire
        # once the next IDB is open. we don't want this, because a new painter
        # will be spun up an it will install its own instance of hooks...
        #

        if self._idp_hooks:
            self._idp_hooks.unhook()
            self._idp_hooks = None

        # spin down the painter as usual
        super(IDAPainter, self).terminate()

    def _notify_status_changed(self, status):

        # enable / disable hook based on the painter being enabled or disabled
        if status:
            self._idp_hooks.hook()
            if idaapi.init_hexrays_plugin():
                idaapi.install_hexrays_callback(self._hxe_callback)
        else:
            self._idp_hooks.unhook()
            if idaapi.init_hexrays_plugin():
                idaapi.remove_hexrays_callback(self._hxe_callback)

        # send the status changed signal...
        super(IDAPainter, self)._notify_status_changed(status)

    #------------------------------------------------------------------------------
    # Paint Actions
    #------------------------------------------------------------------------------

    @execute_paint
    def _paint_instructions(self, instructions):
        """
        Paint instruction level coverage defined by the current database mapping.

        NOTE: we now use 'streaming' mode for instructions rather than this.
        """
        color = struct.pack("I", self.palette.coverage_paint+1)
        for address in instructions:
            set_abits(address, 0x40000)
            nn = netnode(address)
            nn.supset(20, color, 'A')
        self._painted_instructions |= set(instructions)
        self._action_complete.set()

    @execute_paint
    def _clear_instructions(self, instructions):
        """
        Clear paint from the given instructions.

        NOTE: we now use 'streaming' mode for instructions rather than this.
        """
        for address in instructions:
            clr_abits(address, 0x40000)
        self._painted_instructions -= set(instructions)
        self._action_complete.set()

    @execute_paint
    def _paint_nodes(self, node_addresses):
        """
        Paint node level coverage defined by the current database mappings.
        """
        db_coverage = self.director.coverage
        db_metadata = self.director.metadata

        # create a node info object as our vehicle for setting the node color
        node_info = idaapi.node_info_t()
        node_info.bg_color = self.palette.coverage_paint
        node_flags = idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR

        #
        # loop through every node that we have coverage data for, painting them
        # in the IDA graph view as applicable.
        #

        for node_address in node_addresses:

            # retrieve all the necessary structures to paint this node
            node_coverage = db_coverage.nodes.get(node_address, None)
            node_metadata = db_metadata.nodes.get(node_address, None)
            functions = db_metadata.get_functions_by_node(node_address)

            #
            # if we did not get *everything* that we needed, then it is
            # possible the database changesd, or the coverage set changed...
            #
            # this is kind of what we get for not using locks :D but that's
            # okay, just stop painting here and let the painter sort it out
            #

            if not (node_coverage and node_metadata and functions):
                self._msg_queue.put(self.MSG_ABORT)
                node_addresses = node_addresses[:node_addresses.index(node_address)]
                break

            #
            # get_functions_by_node() can return multiple functios (eg, a
            # shared node) but in IDA should only ever return one... so we
            # can pull it out now
            #

            function_metadata = functions[0]

            # ignore nodes that are only partially executed
            if node_coverage.instructions_executed != node_metadata.instruction_count:
                continue

            # do the *actual* painting of a single node instance
            set_node_info(
                function_metadata.address,
                node_metadata.id,
                node_info,
                node_flags
            )

        self._painted_nodes |= set(node_addresses)
        self._action_complete.set()

    @execute_paint
    def _clear_nodes(self, node_addresses):
        """
        Clear paint from the given graph nodes.
        """
        db_metadata = self.director.metadata

        # create a node info object as our vehicle for resetting the node color
        node_info = idaapi.node_info_t()
        node_info.bg_color = idc.DEFCOLOR
        node_flags = idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR

        #
        # loop through every node that we have metadata data for, clearing
        # their paint (color) in the IDA graph view as applicable.
        #

        for node_address in node_addresses:

            # retrieve all the necessary structures to paint this node
            node_metadata = db_metadata.nodes.get(node_address, None)
            functions = db_metadata.get_functions_by_node(node_address)

            #
            # abort if something looks like it changed... read the comments in
            # self._paint_nodes for more verbose information
            #

            if not (node_metadata and functions):
                self._msg_queue.put(self.MSG_ABORT)
                node_addresses = node_addresses[:node_addresses.index(node_address)]
                break

            function_metadata = functions[0]

            # do the *actual* painting of a single node instance
            set_node_info(
                function_metadata.address,
                node_metadata.id,
                node_info,
                node_flags
            )

        self._painted_nodes -= set(node_addresses)
        self._action_complete.set()

    @execute_paint
    def _refresh_ui(self):
        """
        Note that this has been decorated with @execute_paint (vs @execute_ui)
        to help avoid deadlocking on exit.
        """
        for vdui in self._vduis.values():
            if vdui.valid():
                vdui.refresh_ctext(False)
        idaapi.refresh_idaview_anyway()

    def _cancel_action(self, job_id):
        if idaapi.IDA_SDK_VERSION < 710:
            return
        idaapi.cancel_exec_request(job_id)

    #------------------------------------------------------------------------------
    # Painting - HexRays (Decompilation / Source)
    #------------------------------------------------------------------------------

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
        executed_nodes = set(viewkeys(db_coverage.functions[cfunc.entry_ea].nodes))

        #
        # now we loop through every line_number of the decompiled text that claims
        # to have a relationship with a graph node (basic block) and check to see
        # if it contains a node our coverage has marked as executed
        #

        for line_number, line_nodes in iteritems(line2node):

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

    def _hxe_callback(self, event, *args):
        """
        HexRays event handler.
        """

        # decompilation text generation is complete and it is about to be shown
        if event == idaapi.hxe_text_ready:

            # more code-friendly, readable aliases
            vdui = args[0]
            cfunc = vdui.cfunc
            self._vduis[vdui.view_idx] = vdui

            # if there's no coverage data for this function, there's nothing to do
            if not cfunc.entry_ea in self.director.coverage.functions:
                return 0

            # paint the decompilation text for this function
            self.paint_hexrays(cfunc, self.director.coverage)

        # stop tracking vdui's if they close...
        elif event == idaapi.hxe_close_pseudocode:
            vdui = args[0]
            self._vduis.pop(vdui.view_idx, None)

        return 0

#------------------------------------------------------------------------------
# Instruction Paint Streaming (Processor Hooks)
#------------------------------------------------------------------------------

class InstructionPaintHooks(idaapi.IDP_Hooks):
    """
    Hook IDA's processor callbacks to paint instructions on the fly.
    """

    def __init__(self, director, palette):
        super(InstructionPaintHooks, self).__init__()
        self.director = director
        self.palette = palette

    def ev_get_bg_color(self, pcolor, ea):
        if ea not in self.director.coverage.coverage:
            return 0
        bgcolor = ctypes.cast(int(pcolor), ctypes.POINTER(ctypes.c_int))
        bgcolor[0] = self.palette.coverage_paint
        return 1
