import abc
import time
import logging
import threading

from lighthouse.util import *

logger = logging.getLogger("Lighthouse.Painting")

class DatabasePainter(object):
    """
    An asynchronous disassembler database painting engine.
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, director, palette):

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

    def repaint(self):
        """
        Paint coverage defined by the current database mappings.
        """
        self._repaint_requested = True
        self._repaint_request.set()

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
    def _cancel_action(self, job):
        """
        Cancel a paint action using something representing its job.
        """
        pass

    #------------------------------------------------------------------------------
    # Painting - Functions
    #------------------------------------------------------------------------------

    def _paint_function(self, address):
        """
        Paint function instructions & nodes with the current database mappings.
        """

        # collect function information
        function_metadata = self._director.metadata.functions[address]
        function_coverage = self._director.coverage.functions.get(address, None)

        # if no coverage, just clear the function's instruction & nodes
        if not function_coverage:

            # clear instructions
            if not self._async_action(self._clear_instructions, function_metadata.instructions):
                return False

            # clear nodes
            if not self._async_action(self._clear_nodes, function_metadata.nodes.itervalues()):
                return False

            # not interrupted
            return True

        #
        # ~ compute paint job ~
        #

        # compute the painted instructions within this function
        painted = self._painted_instructions & function_metadata.instructions

        # compute the painted instructions that will not get painted over
        stale_instructions = painted - function_coverage.instructions

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

        # not interrupted
        return True

    #--------------------------------------------------------------------------
    # Priority Painting
    #--------------------------------------------------------------------------

    def _priority_paint(self):
        """
        Immediately repaint regions of the database visible to the user.

        Return True upon completion, or False if interrupted.
        """
        return True # NOTE: optional, but recommended

    def _priority_paint_functions(self, target_address):
        """
        Paint functions in the immediate vicinity of the given address.

        This will paint both the instructions & graph nodes of defined functions.
        """
        pass # NOTE: optional, organizational

    def _priority_paint_instructions(self, target_address, ignore=set()):
        """
        Paint instructions in the immediate vicinity of the given address.

        Optionally, one can provide a set of addresses to ignore while painting.
        """
        pass # NOTE: optional, organizational

    #--------------------------------------------------------------------------
    # Asynchronous Painting
    #--------------------------------------------------------------------------

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

            # more code-friendly, readable aliases (db_XX == database_XX)
            db_coverage = self._director.coverage
            db_metadata = self._director.metadata

            start = time.time()
            #------------------------------------------------------------------

            #
            # immediately paint user-visible regions of the the database
            #

            if not self._priority_paint():
                continue # a repaint was requested

            #
            # perform a more comprehensive paint
            #

            # compute the painted instructions that will not get painted over
            stale_inst = self._painted_instructions - db_coverage.coverage

            # compute the painted nodes that will not get painted over
            stale_nodes_ea = self._painted_nodes - db_coverage.nodes.viewkeys()
            stale_nodes = [db_metadata.nodes[ea] for ea in stale_nodes_ea]

            # clear old instruction paint
            if not self._async_action(self._clear_instructions, stale_inst):
                continue # a repaint was requested

            # clear old node paint
            if not self._async_action(self._clear_nodes, stale_nodes):
                continue # a repaint was requested

            # paint new instructions
            if not self._async_action(self._paint_instructions, db_coverage.coverage):
                continue # a repaint was requested

            # paint new nodes
            if not self._async_action(self._paint_nodes, db_coverage.nodes.itervalues()):
                continue # a repaint was requested

            #------------------------------------------------------------------
            end = time.time()
            logger.debug("Full Paint took %s seconds" % (end - start))
            logger.debug(" stale_inst:   %s" % "{:,}".format(len(stale_inst)))
            logger.debug(" fresh inst:   %s" % "{:,}".format(len(db_coverage.coverage)))
            logger.debug(" stale_nodes:  %s" % "{:,}".format(len(stale_nodes)))
            logger.debug(" fresh_nodes:  %s" % "{:,}".format(len(db_coverage.nodes)))

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

            paint_job = paint_action(work_chunk)

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
                self._cancel_action(paint_job)
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
