import ctypes
import logging

from binaryninja import PluginCommand
from binaryninjaui import UIAction, UIActionHandler, Menu

from lighthouse.context import LighthouseContext
from lighthouse.integration.core import LighthouseCore
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.Binja.Integration")

#------------------------------------------------------------------------------
# Lighthouse Binja Integration
#------------------------------------------------------------------------------

class LighthouseBinja(LighthouseCore):
    """
    Lighthouse UI Integration for Binary Ninja.
    """

    def __init__(self):
        super(LighthouseBinja, self).__init__()

    def get_context(self, dctx, startup=True):
        """
        Get the LighthouseContext object for a given database context.

        In Binary Ninja, a dctx is a BinaryView (BV).
        """
        dctx_id = ctypes.addressof(dctx.handle.contents)

        #
        # create a new LighthouseContext if this is the first time a context
        # has been requested for this BNDB / bv
        #

        if dctx_id not in self.lighthouse_contexts:

            # create a new 'context' representing this BNDB / bv
            lctx = LighthouseContext(self, dctx)
            if startup:
                lctx.start()

            # save the created ctx for future calls
            self.lighthouse_contexts[dctx_id] = lctx

        #
        # for binja, we basically *never* want to start the lighthouse ctx
        # when it is first created. this is because binja will *immediately*
        # create a coverage overview widget for every database when it is
        # first opened.
        #
        # this is annoying, because we don't want to actually start up all
        # of the lighthouse threads and subsystems unless the user actually
        # starts trying to use lighthouse for their session.
        #
        # so we initialize the lighthouse context (with start()) on the
        # second context request which will go through the else block
        # below... any subsequent call to start() is effectively a nop!
        #

        else:
            lctx = self.lighthouse_contexts[dctx_id]
            lctx.start()

        # return the lighthouse context object for this database ctx / bv
        return lctx

    def binja_close_context(self, dctx):
        """
        Attempt to close / spin-down the LighthouseContext for the given dctx.

        In Binary Ninja, a dctx is a BinaryView (BV).
        """
        dctx_id = ctypes.addressof(dctx.handle.contents)

        # fetch the LighthouseContext for the closing BNDB
        try:
            lctx = self.lighthouse_contexts.pop(dctx_id)

        #
        # if lighthouse was not actually used for this BNDB / session, then
        # the lookup will fail as there is nothing to spindown
        #

        except KeyError:
            return

        # spin down the closing context (stop threads, cleanup qt state, etc)
        logger.info("Closing a LighthouseContext...")
        lctx.terminate()

    #--------------------------------------------------------------------------
    # UI Integration (Internal)
    #--------------------------------------------------------------------------

    #
    # TODO / HACK / XXX / V35 / 2021: Some of Binja's UI elements (such as the
    # terminal) do not get assigned a BV, even if there is only one open.
    #
    # this is problematic, because if the user 'clicks' onto the terminal, and
    # then tries to execute our UIActions (like 'Load Coverage File'), the
    # given 'context.binaryView' will be None
    #
    # in the meantime, we have to use this workaround that will try to grab
    # the 'current' bv from the dock. this is not ideal, but it will suffice.
    #
    # -----------------
    #
    # XXX: It's now 2024, Binja's UI / API stack has grown a lot. it's more
    # powerful and a bunch of the oddities / hacks lighthouse employed for
    # binja may no longer apply. this whole file should probably be revisited
    # and re-factored at some point point.. sorry if it's hard to follow
    #

    def _interactive_load_file(self, context):
        dctx = disassembler.binja_get_bv_from_dock()
        if not dctx:
            disassembler.warning("Lighthouse requires an open BNDB to load coverage.")
            return
        super(LighthouseBinja, self).interactive_load_file(dctx)

    def _interactive_load_batch(self, context):
        dctx = disassembler.binja_get_bv_from_dock()
        if not dctx:
            disassembler.warning("Lighthouse requires an open BNDB to load coverage.")
            return
        super(LighthouseBinja, self).interactive_load_batch(dctx)

    def _open_coverage_xref(self, context):
        super(LighthouseBinja, self).open_coverage_xref(context.address, context.binaryView)

    def _interactive_coverage_xref(self, context):

        if context is None:
            return

        #
        # this is a special case where we check if the ctx exists rather than
        # blindly creating a new one. again, this is because binja may call
        # this function at random times to decide whether it should display the
        # XREF menu option.
        #
        # but asking whether or not the xref menu option should be shown is not
        # a good indication of 'is the user actually using lighthouse' so we
        # do not want this to be one that creates lighthouse contexts
        #

        dctx = context.binaryView
        if not dctx:
            return

        dctx_id = ctypes.addressof(dctx.handle.contents)
        lctx = self.lighthouse_contexts.get(dctx_id, None)
        if not lctx:
            return

        #
        # is there even any coverage loaded into lighthouse? if not, the user
        # probably isn't even using it. so don't bother showing the xref action
        #

        if not lctx.director.coverage_names:
            return

        if context.view is None:
            return

        view = context.view
        context_menu = view.contextMenu()

        #
        # Create a new, temporary Coverage Xref action to inject into the
        # right click context menu that is being shown...
        #

        action = "Coverage Xref"
        UIAction.registerAction(action)
        action_handler = view.actionHandler()
        action_handler.bindAction(action, UIAction(self._open_coverage_xref))
        context_menu.addAction(action, "Plugins")

    def _is_xref_valid(self, dctx, addr):

        #
        # this is a special case where we check if the ctx exists rather than
        # blindly creating a new one. again, this is because binja may call
        # this function at random times to decide whether it should display the
        # XREF menu option.
        #
        # but asking whether or not the xref menu option should be shown is not
        # a good indidication of 'is the user actually using lighthouse' so we
        # do not want this to be one that creates lighthouse contexts
        #

        dctx_id = ctypes.addressof(dctx.handle.contents)
        lctx = self.lighthouse_contexts.get(dctx_id, None)
        if not lctx:
            return False

        # return True if there appears to be coverage loaded...
        return bool(lctx.director.coverage_names)

    def _open_coverage_overview(self, context):
        dctx = disassembler.binja_get_bv_from_dock()
        if not dctx:
            disassembler.warning("Lighthouse requires an open BNDB to open the overview.")
            return
        super(LighthouseBinja, self).open_coverage_overview(dctx)

    #--------------------------------------------------------------------------
    # Binja Actions
    #--------------------------------------------------------------------------

    ACTION_LOAD_FILE         = "Lighthouse\\Load code coverage file..."
    ACTION_LOAD_BATCH        = "Lighthouse\\Load code coverage batch..."
    ACTION_COVERAGE_XREF     = "Lighthouse\\Coverage Xref"
    ACTION_COVERAGE_OVERVIEW = "Lighthouse\\Open Coverage Overview"

    def _install_load_file(self):
        action = self.ACTION_LOAD_FILE
        UIAction.registerAction(action)
        UIActionHandler.globalActions().bindAction(action, UIAction(self._interactive_load_file))
        Menu.mainMenu("Plugins").addAction(action, "Loading", 0)
        logger.info("Installed the 'Code coverage file' menu entry")

    def _install_load_batch(self):
        action = self.ACTION_LOAD_BATCH
        UIAction.registerAction(action)
        UIActionHandler.globalActions().bindAction(action, UIAction(self._interactive_load_batch))
        Menu.mainMenu("Plugins").addAction(action, "Loading", 1)
        logger.info("Installed the 'Code coverage batch' menu entry")

    def _install_open_coverage_xref(self):
        action = self.ACTION_COVERAGE_XREF
        UIAction.registerAction(action)
        UIActionHandler.globalActions().bindAction(action, UIAction(lambda context: None, self._interactive_coverage_xref))
        Menu.mainMenu("Plugins").addAction(action, "Loading", 2)

    # NOTE/V35: Binja automatically creates View --> Show Coverage Overview
    def _install_open_coverage_overview(self):
        action = self.ACTION_COVERAGE_OVERVIEW
        UIAction.registerAction(action)
        UIActionHandler.globalActions().bindAction(action, UIAction(self._open_coverage_overview))
        Menu.mainMenu("Plugins").addAction(action, "Windows", 0)
        logger.info("Installed the 'Open Coverage Overview' menu entry")

    # NOTE/V35: Binja doesn't really 'unload' plugins, so whatever...
    def _uninstall_load_file(self):
        pass
    def _uninstall_load_batch(self):
        pass
    def _uninstall_open_coverage_xref(self):
        pass
    def _uninstall_open_coverage_overview(self):
        pass
