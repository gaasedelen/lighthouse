import os
import collections

from ..coverage_file import CoverageFile

class ModOffData(CoverageFile):
    """
    A module+offset log parser.
    """

    def __init__(self, filepath):
        super(ModOffData, self).__init__(filepath)

    #--------------------------------------------------------------------------
    # Public
    #--------------------------------------------------------------------------

    def get_offsets(self, module_name):
        return self.modules.get(module_name, {}).keys()

    #--------------------------------------------------------------------------
    # Parsing Routines - Top Level
    #--------------------------------------------------------------------------

    def _parse(self):
        """
        Parse modoff coverage from the given log file.
        """
        modules = collections.defaultdict(lambda: collections.defaultdict(int))
        with open(self.filepath) as f:
            for line in f:
                trimmed = line.strip()

                # skip empty lines
                if not len(trimmed): continue

                # comments can start with ';' or '#'
                if trimmed[0] in [';', '#']: continue

                module_name, bb_offset = line.rsplit("+", 1)
                modules[module_name][int(bb_offset, 16)] += 1
        self.modules = modules
