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

    def get_context(self, dctx):
        """
        Get the LighthouseContext object for a given disassembler context.
        """
        dctx_id = ctypes.addressof(dctx.handle.contents)

        # create a new LighthouseContext if this is a new disassembler ctx / bv
        if dctx_id not in self.lighthouse_contexts:
            print("Creating new Lctx!", dctx)
            self.lighthouse_contexts[dctx_id] = LighthouseContext(self, dctx)
        else:
            print("Using ctx...", dctx)

        # return the lighthouse context object for this disassembler ctx / bv
        return self.lighthouse_contexts[dctx_id]

    #--------------------------------------------------------------------------
    # UI Integration (Internal)
    #--------------------------------------------------------------------------

    #
    # NOTE / HACK / XXX: Some of Binja's UI elements (such as the terminal) do
    # not get assigned a BV, even if there is only one open.
    #
    # this is problematic, because if the user 'clicks' onto the termial, and
    # then tries to execute our UIActions (like 'Load Coverage File'), the
    # given 'contxet.binaryView' will be None
    #
    # in the meantime, we have to use this workaround that will try to grab
    # the 'current' bv from the dock. this is not ideal, but it will suffice.
    #
    # TODO/V35: There is no good way to enable/disable UIActions on the fly...
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

    def _open_coverage_xref(self, bv, addr):
        super(LighthouseBinja, self).open_coverage_xref(bv, addr)

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
        Menu.mainMenu("Tools").addAction(action, "Loading", 0)
        logger.info("Installed the 'Code coverage file' menu entry")

    def _install_load_batch(self):
        action = self.ACTION_LOAD_BATCH
        UIAction.registerAction(action)
        UIActionHandler.globalActions().bindAction(action, UIAction(self._interactive_load_batch))
        Menu.mainMenu("Tools").addAction(action, "Loading", 1)
        logger.info("Installed the 'Code coverage batch' menu entry")

    def _install_open_coverage_xref(self):
        PluginCommand.register_for_address(
            self.ACTION_COVERAGE_XREF,
            "Open the coverage xref window",
            self._open_coverage_xref,
            lambda bv, addr: bool(self.get_context(bv).director.aggregate.instruction_percent)
        )

        # TODO: enable as a UI action once we can disable/disable them on the fly
        #action = self.ACTION_COVERAGE_XREF
        #UIAction.registerAction(action)
        #UIActionHandler.globalActions().bindAction(action, UIAction(self._open_coverage_xref))
        #Menu.mainMenu("Tools").addAction(action, "Coverage Xref")
        #logger.info("Installed the 'Coverage Xref' menu entry")

    def _install_open_coverage_overview(self):
        #action = self.ACTION_COVERAGE_OVERVIEW
        #UIAction.registerAction(action)
        #UIActionHandler.globalActions().bindAction(action, UIAction(self.open_coverage_overview))
        #Menu.mainMenu("Tools").addAction("Lighthouse", action, "Coverage Overview")
        logger.info("Installed the 'Coverage Overview' menu entry")

    #
    # TODO/V35: No good signals to unload (core) UI entries on
    #

    def _uninstall_load_file(self):
        action = self.ACTTION_LOAD_FILE
        UIActionHandler.globalActions().unbindAction(action)
        Menu.mainMenu("Tools").removeAction(action)
        UIAction.unregisterAction(action)
        logger.info("Uninstalled the 'Code coverage file' menu entry")

    def _uninstall_load_batch(self):
        action = self.ACTTION_LOAD_BATCH
        UIActionHandler.globalActions().unbindAction(action)
        Menu.mainMenu("Tools").removeAction(action)
        UIAction.unregisterAction(action)
        logger.info("Uninstalled the 'Code coverage batch' menu entry")

    def _uninstall_open_coverage_xref(self):
        pass
        #action = self.ACTTION_COVERAGE_XREF
        #UIActionHandler.globalActions().unbindAction(action)
        ##Menu.mainMenu("Tools").removeAction(action)
        #UIAction.unregisterAction(action)
        #logger.info("Uninstalled the 'Coverage Xref' menu entry")

    def _uninstall_open_coverage_overview(self):
        #action = self.ACTTION_COVERAGE_OVERVIEW
        #UIActionHandler.globalActions().unbindAction(action)
        #Menu.mainMenu("Tools").removeAction(action)
        #UIAction.unregisterAction(action)
        logger.info("Uninstalled the 'Coverage Overview' menu entry")

