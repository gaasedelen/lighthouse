import logging

import cutter
from PySide2.QtWidgets import QAction
from PySide2.QtCore import QObject, SIGNAL
from lighthouse.core import Lighthouse
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.Cutter.Integration")


#------------------------------------------------------------------------------
# Lighthouse Cutter Integration
#------------------------------------------------------------------------------

class LighthouseCutter(Lighthouse):
    """
    Lighthouse UI Integration for Cutter.
    """

    def __init__(self, plugin, main):
        self.plugin = plugin
        self.main = main
        super(LighthouseCutter, self).__init__()
        disassembler.main = main

    def interactive_load_file(self, unk):
        super(LighthouseCutter, self).interactive_load_file()

    def interactive_load_batch(self, unk):
        super(LighthouseCutter, self).interactive_load_batch()

    def _install_load_file(self):
        action = QAction("Lighthouse - Load code coverage file...", self.main)
        action.triggered.connect(self.interactive_load_file)
        self.main.addMenuFileAction(action)
        logger.info("Installed the 'Code coverage file' menu entry")

    def _install_load_batch(self):
        action = QAction("Lighthouse - Load code coverage batch...", self.main)
        action.triggered.connect(self.interactive_load_batch)
        self.main.addMenuFileAction(action)
        logger.info("Installed the 'Code coverage batch' menu entry")

    def _install_open_coverage_overview(self):
        logger.info("TODO - Coverage Overview menu entry?")

    def _uninstall_load_file(self):
        pass

    def _uninstall_load_batch(self):
        pass

    def _uninstall_open_coverage_overview(self):
        pass

