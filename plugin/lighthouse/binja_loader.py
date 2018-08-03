from binaryninja import PluginCommand
from lighthouse.core import Lighthouse
from lighthouse.util.log import logger

class LighthouseBinja(Lighthouse):
    """
    TODO
    """

    def __init__(self):
        super(LighthouseBinja, self).__init__()

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
            lambda x: lighthouse.interactive_load_file()
        )

try:
    lighthouse = LighthouseBinja()
    lighthouse.load()
except Exception as e:
    logger.error(e)
    print e

