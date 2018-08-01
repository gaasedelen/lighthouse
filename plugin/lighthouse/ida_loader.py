import idaapi

from lighthouse.core import Lighthouse
from lighthouse.util.log import logger

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return LighthouseIDA()

class LighthouseIDA(idaapi.plugin_t):
    """
    The Lighthouse IDA Plugin Loader.
    """

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
        self._lighthouse = Lighthouse()

        # attempt plugin initialization
        try:
            self._lighthouse._install_plugin()

        # failed to initialize or integrate the plugin, log and skip loading
        except Exception as e:
            logger.exception("Failed to initialize Lighthouse in IDA")
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

        # attempt to cleanup and uninstall our plugin instance
        try:
            self._lighthouse._uninstall_plugin()

        # failed to cleanly remove the plugin, log failure
        except Exception as e:
            logger.exception("Failed to cleanly unload Lighthouse from IDA.")

