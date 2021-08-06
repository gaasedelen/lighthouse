import collections
from ..coverage_file import CoverageFile

# 'known' instruction pointer labels from Tenet traces
INSTRUCTION_POINTERS = ['RIP', 'PC']

class TenetData(CoverageFile):
    """
    A Tenet trace log parser.
    """

    def __init__(self, filepath):
        self._hitmap = {}
        super(TenetData, self).__init__(filepath)

    #--------------------------------------------------------------------------
    # Public
    #--------------------------------------------------------------------------

    def get_addresses(self, module_name=None):
        return self._hitmap.keys()

    #--------------------------------------------------------------------------
    # Parsing Routines - Top Level
    #--------------------------------------------------------------------------

    def _parse(self):
        """
        Parse absolute instruction addresses from the given Tenet trace.
        """
        hitmap = collections.defaultdict(int)

        with open(self.filepath) as f:

            while True:

                # read 128mb chunks of 'lines' from the file
                lines = f.readlines(1024 * 1024 * 128)

                # no more lines to process, break
                if not lines:
                    break

                # parse the instruction addresses from lines, into the hitmap
                self._process_lines(lines, hitmap)

        # save the hitmap if we completed parsing without crashing
        self._hitmap = hitmap

    def _process_lines(self, lines, hitmap):
        """
        Parse instruction addresses out of the given text lines.
        """

        for line in lines:

            # split the line (an execution delta) into its individual entries
            delta = line.split(",")

            # process each item (a name=value pair) in the execution delta
            for item in delta:

                # split name/value pair, and normalize the name for matching
                name, value = item.split("=")
                name = name.upper()

                # ignore entries that are not the instruction pointer
                if not name in INSTRUCTION_POINTERS:
                    continue

                # save the parsed instruction pointer address to the hitmap
                address = int(value, 16)
                hitmap[address] += 1

                # break beacuse we don't expect two IP's on the same line
                break

            # continue to the next line
            # ...

        # done parsing this chunk of lines
        return
