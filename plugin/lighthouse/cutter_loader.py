import logging

import CutterBindings
from lighthouse.cutter_integration import LighthouseCutter

logger = logging.getLogger('Lighthouse.Cutter.Loader')

#------------------------------------------------------------------------------
# Lighthouse Cutter Loader
#------------------------------------------------------------------------------
#
#    The Cutter plugin loading process is quite easy. All we need is a function
#    create_cutter_plugin that returns an instance of CutterBindings.CutterPlugin

class LighthouseCutterPlugin(CutterBindings.CutterPlugin):
    name = 'Ligthouse'
    description = 'Lighthouse plugin for Cutter.'
    version = '1.0'
    author = 'xarkes'

    def __init__(self):
        super(LighthouseCutterPlugin, self).__init__()

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        self.main = main
        self.ui = LighthouseCutter(self, main)
        self.ui.load()


def create_cutter_plugin():
    try:
        plugin = LighthouseCutterPlugin()
        return plugin
    except Exception as e:
        print('ERROR ---- ', e)
        import sys, traceback
        traceback.print_exc()
        raise e

