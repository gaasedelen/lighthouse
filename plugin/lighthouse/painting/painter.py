import abc
import time
import logging
import threading

from lighthouse.util import *
from lighthouse.coverage import FunctionCoverage

logger = logging.getLogger("Lighthouse.Painting")

class DatabasePainter(object):
    """
    An asynchronous disassembler database painting engine.
    """
    __metaclass__ = abc.ABCMeta

    MSG_ABORT = -1
    MSG_TERMINATE = 0
    MSG_REPAINT = 1
    MSG_CLEAR = 2
    MSG_FORCE_CLEAR = 3
    MSG_REBASE = 4

    def __init__(self, lctx, director, palette):

        #----------------------------------------------------------------------
        # Misc
        #----------------------------------------------------------------------

        self.lctx = lctx
        self.palette = palette
        self.director = director
        self._enabled = False
        self._started = False

        #----------------------------------------------------------------------
        # Painted State
        #----------------------------------------------------------------------

        #
        # the coverage painter maintains its own internal record of what
        # instruction addresses and graph nodes it has painted.
        #

        self._imagebase = BADADDR
        self._painted_nodes = set()
        self._painted_instructions = set()

        #
        # these toggles will let the core painter (this class) know that it
        # does not have to order explicit paints of instructions or nodes.
        #
        # this is because a disassembler-specific painter may be able to hook
        # unique callbacks for painting graphs nodes or instructions
        # 'on-the-fly' as they are rendered.
        #
        # these types of paints are ephermal and the most performant, they
        # also will not need to be tracked by the painter.
        #

        self._streaming_nodes = False
        self._streaming_instructions = False

        #----------------------------------------------------------------------
        # Async
        #----------------------------------------------------------------------

        #
        # to communicate with the asynchronous painting thread, we send a
        # a message via the thread event to signal a new paint request, and
        # use the repaint_requested bool to interrupt a running paint request.
        #

        self._action_complete = threading.Event()
        self._msg_queue = queue.Queue()
        self._end_threads = False

        #
        # asynchronous database painting thread
        #

        self._painting_worker = threading.Thread(
            target=self._async_database_painter,
            name="DatabasePainter"
        )

        #----------------------------------------------------------------------
        # Callbacks
        #----------------------------------------------------------------------

        # painter callbacks
        self._status_changed_callbacks = []

        # register for cues from the director
        self.director.coverage_switched(self.repaint)
        self.director.coverage_modified(self.repaint)
        self.director.refreshed(self.check_rebase)

    def start(self):
        """
        Start the painter.
        """
        if self._started:
            return

        # start the painter thread
        self._painting_worker.start()

        # all done
        self._started = True
        self.set_enabled(True)

    #--------------------------------------------------------------------------
    # Status
    #--------------------------------------------------------------------------

    @property
    def enabled(self):
        """
        Return the active painting status of the painter.
        """
        return self._enabled

    def set_enabled(self, enabled):
        """
        Enable or disable the painter.
        """

        # enabled/disabled status is not changing, ignore...
        if enabled == self._enabled:
            return

        lmsg("%s painting..." % ("Enabling" if enabled else "Disabling"))
        self._enabled = enabled

        # paint or clear the database based on the change of status...
        if enabled:
            self._send_message(self.MSG_REPAINT)
        else:
            self._send_message(self.MSG_CLEAR)

        # notify listeners that the painter has been enabled/disabled
        self._notify_status_changed(enabled)

    #--------------------------------------------------------------------------
    # Commands
    #--------------------------------------------------------------------------

    def terminate(self):
        """
        Cleanup & terminate the painter.
        """
        self._end_threads = True
        self._msg_queue.put(self.MSG_TERMINATE)
        try:
            self._painting_worker.join()
        except RuntimeError: # thread was never started...
            pass

        # best effort to free up resources & improve interpreter spindown
        del self._painted_nodes
        del self._painted_instructions
        del self._status_changed_callbacks

    def repaint(self):
        """
        Paint coverage defined by the current database mappings.
        """
        self._send_message(self.MSG_REPAINT)

    def force_clear(self):
        """
        Clear all paint from the current database (based on metadata)
        """
        self._send_message(self.MSG_FORCE_CLEAR)
        self.set_enabled(False)

    def check_rebase(self):
        """
        Perform a rebase on the painted data cache (if necessary).
        """
        self._send_message(self.MSG_REBASE)
        self._send_message(self.MSG_REPAINT)

    def _send_message(self, message):
        """
        Queue a painter command for execution.
        """
        if not self._started:
            return
        self._msg_queue.put(message)

    #--------------------------------------------------------------------------
    # Commands
    #--------------------------------------------------------------------------

    def status_changed(self, callback):
        """
        Subscribe a callback for coverage switch events.
        """
        register_callback(self._status_changed_callbacks, callback)

    def _notify_status_changed(self, status):
        """
        Notify listeners of a coverage switch event.
        """
        notify_callback(self._status_changed_callbacks, status)

    #--------------------------------------------------------------------------
    # Paint Primitives
    #--------------------------------------------------------------------------

    @abc.abstractmethod
    def _paint_instructions(self, instructions):
        """
        Paint instruction coverage defined by the current database mapping.
        """
        pass

    @abc.abstractmethod
    def _clear_instructions(self, instructions):
        """
        Clear paint from the given instructions.
        """
        pass

    @abc.abstractmethod
    def _paint_nodes(self, nodes_coverage):
        """
        Paint node coverage defined by the current database mappings.
        """
        pass

    @abc.abstractmethod
    def _clear_nodes(self, nodes_metadata):
        """
        Clear paint from the given graph nodes.
        """
        pass

    @abc.abstractmethod
    def _refresh_ui(self):
        """
        Refresh the disassembler UI to ensure paint is rendered.
        """
        pass

    @abc.abstractmethod
    def _cancel_action(self, job):
        """
        Cancel a paint action using something representing its job.
        """
        pass

    #------------------------------------------------------------------------------
    # Painting - High Level
    #------------------------------------------------------------------------------

    def _priority_paint(self):
        """
        Immediately repaint regions of the database visible to the user.

        Return True upon completion, or False if interrupted.
        """
        if self._streaming_instructions and self._streaming_nodes:
            return True

        # get current function / user location in the database
        cursor_address = disassembler[self.lctx].get_current_address()

        # attempt to paint the functions in the immediate cursor vicinity
        result = self._priority_paint_functions(cursor_address)

        # force a refresh *now* as this is a prority painting
        self._refresh_ui()

        # all done
        return result

    def _priority_paint_functions(self, target_address, neighbors=1):
        """
        Paint functions in the immediate vicinity of the given address.

        This will paint both the instructions & graph nodes of defined functions.
        """
        db_metadata = self.director.metadata
        db_coverage = self.director.coverage
        blank_coverage = FunctionCoverage(BADADDR)

        # get the function metadata for the function closest to our cursor
        function_metadata = db_metadata.get_closest_function(target_address)
        if not function_metadata:
            return False

        # select the range of functions around us that we would like to paint
        func_num = db_metadata.get_function_index(function_metadata.address)
        func_num_start = max(func_num - neighbors, 0)
        func_num_end   = min(func_num + neighbors + 1, len(db_metadata.functions) - 1)

        # repaint the specified range of functions
        for current_num in xrange(func_num_start, func_num_end):

            # get the next function to paint
            function_metadata = db_metadata.get_function_by_index(current_num)
            if not function_metadata:
                continue

            # get the function coverage data for the target address
            function_address = function_metadata.address
            function_coverage = db_coverage.functions.get(function_address, blank_coverage)

            if not self._streaming_nodes:

                # clear nodes
                must_clear = sorted(set(function_metadata.nodes) - set(function_coverage.nodes))
                self._action_complete.clear()
                self._clear_nodes(must_clear)
                self._action_complete.wait()

                # paint nodes
                must_paint = sorted(function_coverage.nodes)
                self._action_complete.clear()
                self._paint_nodes(must_paint)
                self._action_complete.wait()

            if not self._streaming_instructions:

                # clear instructions
                must_clear = sorted(function_metadata.instructions - function_coverage.instructions)
                self._action_complete.clear()
                self._clear_instructions(must_clear)
                self._action_complete.wait()

                # paint instructions
                must_paint = sorted(function_coverage.instructions)
                self._action_complete.clear()
                self._paint_instructions(must_paint)
                self._action_complete.wait()

        # paint finished successfully
        return True

    def _paint_database(self):
        """
        Repaint the current database based on the current state.
        """
        logger.debug("Painting database...")

        # more code-friendly, readable aliases (db_XX == database_XX)
        db_coverage = self.director.coverage
        db_metadata = self.director.metadata

        start = time.time()
        #------------------------------------------------------------------

        # initialize imagebase if it hasn't been already...
        if self._imagebase == BADADDR:
            self._imagebase = db_metadata.imagebase

        # immediately paint user-visible regions of the database
        if not self._priority_paint():
            return False # a repaint was requested

        #
        # if the painter is not capable of 'streaming' the coverage paint,
        # then we must explicitly paint the instructions & nodes here
        #

        if not self._streaming_instructions:

            # compute the painted instructions that will not get painted over
            stale_partial_inst = self._painted_instructions & db_coverage.partial_instructions
            stale_instr = self._painted_instructions - db_coverage.coverage
            stale_instr |= stale_partial_inst

            # clear old instruction paint
            if not self._async_action(self._clear_instructions, stale_instr):
                return False # a repaint was requested

            # paint new instructions
            new_instr = sorted(db_coverage.coverage - self._painted_instructions)
            if not self._async_action(self._paint_instructions, new_instr):
                return False # a repaint was requested

        if not self._streaming_nodes:

            # compute the painted nodes that will not get painted over
            stale_nodes = self._painted_nodes - viewkeys(db_coverage.nodes)
            stale_nodes |= db_coverage.partial_nodes

            # clear old node paint
            if not self._async_action(self._clear_nodes, stale_nodes):
                return False # a repaint was requested

            # paint new nodes
            new_nodes = sorted(viewkeys(db_coverage.nodes) - self._painted_nodes)
            if not self._async_action(self._paint_nodes, new_nodes):
                return False # a repaint was requested

        #------------------------------------------------------------------
        end = time.time()
        logger.debug(" - Painting took %.2f seconds" % (end - start))

        # paint finished successfully
        return True

    def _clear_database(self):
        """
        Clear all paint from the current database using the known paint state.
        """
        logger.debug("Clearing database paint...")
        start = time.time()
        #------------------------------------------------------------------

        db_metadata = self.director.metadata

        # clear all instructions
        if not self._streaming_instructions:
            if not self._async_action(self._clear_instructions, self._painted_instructions):
                return False # a repaint was requested

        # clear all nodes
        if not self._streaming_nodes:
            if not self._async_action(self._clear_nodes, self._painted_nodes):
                return False # a repaint was requested

        #------------------------------------------------------------------
        end = time.time()
        logger.debug(" - Database paint cleared in %.2f seconds..." % (end-start))

        # sanity checks...
        assert self._painted_nodes == set()
        assert self._painted_instructions == set()

        # paint finished successfully
        return True

    def _force_clear_database(self):
        """
        Forcibly clear the paint from all known database addresses.
        """
        db_metadata = self.director.metadata

        text = "Forcibly clearing all paint from database..."
        logger.debug(text)

        #
        # NOTE: forcefully clearing the database of paint can take a long time
        # in certain cases, so we want to block the user from doing anything
        # to the database while we're working.
        #
        # we will pop up a waitbox to block them, but we have to be careful as
        # a *modal* waitbox will conflict with IDA's processing of MFF_WRITE
        # requests making it wait for the waitbox to close before processing
        #
        # therefore, we put in a little bodge wire here to make sure the
        # waitbox is *not* modal for IDA... but will be in the normal case.
        # it also helps that IDA will be busy processing our 'write' requests,
        # so the UI will be mostly frozen to the user anyway!
        #

        is_modal = bool(disassembler.NAME != "IDA")
        disassembler.execute_ui(disassembler.show_wait_box)(text, is_modal)

        start = time.time()
        #------------------------------------------------------------------

        self._action_complete.clear()
        self._clear_instructions(sorted(db_metadata.instructions))
        self._action_complete.wait()

        self._action_complete.clear()
        self._clear_nodes(sorted(db_metadata.nodes))
        self._action_complete.wait()

        #------------------------------------------------------------------
        end = time.time()

        logger.debug(" - Database paint cleared in %.2f seconds..." % (end-start))
        disassembler.execute_ui(disassembler.hide_wait_box)()

        # paint finished successfully
        return True

    def _rebase_database(self):
        """
        Rebase the active database paint.

        TODO/XXX: there may be some edgecases where painting can be wrong if
                  a rebase occurs while the painter is running.
        """
        db_metadata = self.director.metadata
        instructions = db_metadata.instructions
        nodes = viewvalues(db_metadata.nodes)

        # a rebase has not occurred
        if not db_metadata.cached or (db_metadata.imagebase == self._imagebase):
            return False

        # compute the offset of the rebase
        rebase_offset = db_metadata.imagebase - self._imagebase

        # rebase the cached addresses of what we have painted
        self._painted_nodes = set([address+rebase_offset for address in self._painted_nodes])
        self._painted_instructions = set([address+rebase_offset for address in self._painted_instructions])
        self._imagebase = db_metadata.imagebase

        # a rebase has been observed
        return True

    #--------------------------------------------------------------------------
    # Asynchronous Painting
    #--------------------------------------------------------------------------

    def _async_database_painter(self):
        try:
            self._async_database_painter2()
        except:
            lmsg("PAINTER THREAD CRASHED :'(")
            logger.exception("Painter crashed...")

    def _async_database_painter2(self):
        """
        Asynchronous database painting worker loop.
        """
        logger.debug("Starting DatabasePainter thread...")

        #
        # Asynchronous Database Painting Loop
        #

        while not self._end_threads:

            # wait for the next command to come through
            action = self._msg_queue.get()

            # repaint the database based on the current state
            if action == self.MSG_REPAINT:
                result = self._paint_database()

            # clear database base on the current state
            elif action == self.MSG_CLEAR:
                result = self._clear_database()

            # clear all possible database paint
            elif action == self.MSG_FORCE_CLEAR:
                result = self._force_clear_database()

            # check for a rebase of the painted data
            elif action == self.MSG_REBASE:
                result = self._rebase_database()

            # thrown internally to escape a stale paint, just ignore
            elif action == self.MSG_ABORT:
                continue

            # spin down the painting thread (this thread)
            elif action == self.MSG_TERMINATE:
                break

            # unknown command
            else:
                logger.error("UNKNOWN COMMAND! %s" % str(action))
                break

            # refresh the UI to ensure paint changes are rendered
            self._refresh_ui()

        # thread exit
        logger.debug("Exiting DatabasePainter thread...")

    def _async_action(self, paint_action, work_iterable):
        """
        Split a normal paint routine into interruptable chunks.

        Internal routine for asynchrnous painting.
        """
        CHUNK_SIZE = 1500 # somewhat arbitrary

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

            paint_job = paint_action(work_chunk)

            #
            # wait for the asynchronous paint event to complete or a signal that
            # we should end this thread (via end_threads)
            #

            while not (self._action_complete.wait(timeout=0.2) or self._end_threads):
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
                self._cancel_action(paint_job)
                return False

            #
            # the operation has been interrupted by a repaint request, bail
            # immediately so that we can process the next repaint
            #

            if not self._msg_queue.empty():
                return False

        # operation completed successfully
        return True
