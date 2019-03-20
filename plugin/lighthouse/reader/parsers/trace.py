import collections
from ..coverage_file import CoverageFile

class TraceData(CoverageFile):
    """
    An instruction (or basic block) address trace log parser.
    """

    def __init__(self, filepath):
        self._hitmap = {}
        super(TraceData, self).__init__(filepath)

    #--------------------------------------------------------------------------
    # Public
    #--------------------------------------------------------------------------

    def get_addresses(self, module_name=None):
        if module_name:
            raise ValueError("No module mapping in this log format")
        return self._hitmap.keys()

    #--------------------------------------------------------------------------
    # Parsing Routines - Top Level
    #--------------------------------------------------------------------------

    def _parse(self):
        """
        Parse absolute address coverage from the given log file.
        """
        hitmap = collections.defaultdict(int)
        with open(self.filepath) as f:
            for line in f:
                hitmap[int(line, 16)] += 1
        self._hitmap = hitmap
