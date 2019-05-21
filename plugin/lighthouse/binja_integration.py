import logging

from binaryninja import PluginCommand
from lighthouse.core import Lighthouse
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.Binja.Integration")

#------------------------------------------------------------------------------
# Lighthouse Binja Integration
#------------------------------------------------------------------------------

class LighthouseBinja(Lighthouse):
    """
    Lighthouse UI Integration for Binary Ninja.
    """

    def __init__(self):
        super(LighthouseBinja, self).__init__()

    def interactive_load_file(self, bv):
        disassembler.bv = bv
        super(LighthouseBinja, self).interactive_load_file()

    def interactive_load_batch(self, bv):
        disassembler.bv = bv
        super(LighthouseBinja, self).interactive_load_batch()

    def interactive_load_batch(self, bv):
        disassembler.bv = bv
        super(LighthouseBinja, self).open_coverage_overview()

    def _install_load_file(self):
        PluginCommand.register(
            r"Lighthouse\Load code coverage file...",
            "Load individual code coverage file(s)",
            self.interactive_load_file
        )
        logger.info("Installed the 'Code coverage file' menu entry")

    def _install_load_batch(self):
        PluginCommand.register(
            r"Lighthouse\Load code coverage batch...",
            "Load and aggregate code coverage files",
            self.interactive_load_batch
        )
        logger.info("Installed the 'Code coverage batch' menu entry")

    def _install_open_coverage_overview(self):
        PluginCommand.register(
            r"Lighthouse\Coverage Overview",
            "Open the database code coverage overview",
            self.interactive_load_batch
        )
        logger.info("Installed the 'Coverage Overview' menu entry")

    # TODO/V35: No good signals to unload (core) plugin on
    def _uninstall_load_file(self):
        pass

    def _uninstall_load_batch(self):
        pass

    def _uninstall_open_coverage_overview(self):
        pass
