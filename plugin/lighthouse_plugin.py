from idaapi import plugin_t

from lighthouse.util import start_logging, lmsg
logger = start_logging()

#------------------------------------------------------------------------------
# IDA Plugin
#------------------------------------------------------------------------------

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return lighthouse_t()

class lighthouse_t(plugin_t):
    """
    The IDA Plugin for Lighthouse.
    """

    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_MOD
    comment = "Code Coverage Visualization"
    help = ""
    wanted_name = "Lighthouse"
    wanted_hotkey = ""

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """
        lmsg("Hello World")

        logger.info("Successfully initialized")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.

        Lighthouse should never be run as a script.
        """
        msg("Lighthouse cannot be loaded as a script")

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """
        logger.info("-"*70)
        logger.info("Lighthouse has terminated")
