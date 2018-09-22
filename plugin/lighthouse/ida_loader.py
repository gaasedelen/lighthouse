import logging

import idaapi
from lighthouse.util.log import lmsg
from lighthouse.ida_integration import LighthouseIDA

logger = logging.getLogger("Lighthouse.IDA.Loader")

#------------------------------------------------------------------------------
# Lighthouse IDA Loader
#------------------------------------------------------------------------------
#
#    This file contains a stub 'plugin' class for Lighthouse as required by
#    IDA Pro. Practically speaking, there should be little to *no* logic placed
#    in this file because it is disassembler-specific.
#
#    When IDA Pro is starting up, it will import all python files placed in its
#    root plugin folder. It will then attempt to call PLUGIN_ENTRY() on each of
#    the imported 'plugins'. We import PLUGIN_ENTRY into lighthouse_plugin.py
#    so that IDA can see it.
#
#    PLUGIN_ENTRY() is expected to return a plugin object (LighthouseIDAPlugin)
#    derived from idaapi.plugin_t. IDA will register the plugin, and interface
#    with the plugin object to load / unload the plugin at certain times, per
#    its configuration (flags, hotkeys).
#
#    There should be virtually no reason for you to modify this file.
#

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return LighthouseIDAPlugin()

class LighthouseIDAPlugin(idaapi.plugin_t):
    """
    The IDA plugin stub for Lighthouse.
    """

    #
    # Plugin flags:
    # - PLUGIN_MOD: Lighthouse is a plugin that may modify the database
    # - PLUGIN_PROC: Load/unload Lighthouse when an IDB opens / closes
    # - PLUGIN_HIDE: Hide Lighthouse from the IDA plugin menu
    #

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_MOD | idaapi.PLUGIN_HIDE
    comment = "Code Coverage Explorer"
    help = ""
    wanted_name = "Lighthouse"
    wanted_hotkey = ""

    #--------------------------------------------------------------------------
    # IDA Plugin Overloads
    #--------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """
        try:
            self._lighthouse = LighthouseIDA()
            self._lighthouse.load()
        except Exception as e:
            lmsg("Failed to initialize Lighthouse")
            logger.exception("Exception details:")
            return idaapi.PLUGIN_SKIP

        # tell IDA to keep the plugin loaded (everything is okay)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        idaapi.warning("Lighthouse cannot be run as a script in IDA.")

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """
        try:
            self._lighthouse.unload()
            self._lighthouse = None
        except Exception as e:
            logger.exception("Failed to cleanly unload Lighthouse from IDA.")

