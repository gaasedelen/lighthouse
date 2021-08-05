import logging

import CutterBindings
from lighthouse.integration.cutter_integration import LighthouseCutter
from lighthouse.util.disassembler import disassembler, DisassemblerContextAPI

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
        self.ui = None

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        self.main = main
        self.ui = LighthouseCutter(self, main)
        disassembler.main = main
        self.ui.load()

    def terminate(self):
        if self.ui:
            self.ui.unload()


def create_cutter_plugin():
    try:
        return LighthouseCutterPlugin()
    except Exception as e:
        print('ERROR ---- ', e)
        import sys, traceback
        traceback.print_exc()
        raise e

