import logging

from binaryninja import PluginCommand

from lighthouse.core import Lighthouse
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.Integration.Binja")

#------------------------------------------------------------------------------
# Lighthouse Binja Integration
#------------------------------------------------------------------------------

class LighthouseBinja(Lighthouse):
    """
    TODO
    """

    def __init__(self):
        super(LighthouseBinja, self).__init__()

    def interactive_load_file(self, bv):
        disassembler.bv = bv
        super(LighthouseBinja, self).interactive_load_file()

    def _install_load_batch(self):
        pass

    def _install_open_coverage_overview(self):
        pass

    def _install_load_file(self):
        """
        TODO
        """
        PluginCommand.register(
            "Load code coverage file...",
            "Load individual code coverage file(s)",
            self.interactive_load_file
        )
