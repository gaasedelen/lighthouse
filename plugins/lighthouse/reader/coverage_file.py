import abc

class CoverageFile(object):
    """
    Templated class for Lighthouse-compatible code coverage file reader.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __init__(self, filepath=None):
        self.filepath = filepath
        self.modules = {}
        self._parse()

    #--------------------------------------------------------------------------
    # Parsing Routines
    #--------------------------------------------------------------------------

    @abc.abstractmethod
    def _parse(self):
        """
        Load and parse coverage data from the file defined by self.filepath

        Within this function, a custom CoverageFile is expected to attempt to
        parse the coverage file from disk. If the coverage file does not appear
        to match the format expected by this parser -- that is okay.

        Should this parser crash and burn, the CoverageReader will simply move
        on to the next available parser and discard this attempt.

        This function should *only* parse & categorize the coverage data that
        it loads from disk. If this function returns without error, the
        CoverageReader will attempt to call one of the get() functions later
        to retrieve the data you have loaded.

        The best coverage file formats will contain some sort of mapping
        for the coverage data that ties it to a module or binary that was in
        the instrumented process space.

        If this mapping in known, then this function should strive to store
        the coverage data in the self.modules dictionary, where

            self.modules[module_name] = [ coverage_addresses ]

        """
        raise NotImplementedError("Coverage parser not implemented")

    #--------------------------------------------------------------------------
    # Public
    #--------------------------------------------------------------------------

    #
    # if you are writing a parser for a custom coverage file format, your
    # parser is *REQUIRED* to implement one of the following routines.
    #
    # the CoverageReader well attempt to retrieve parsed data from this class
    # using one of the function below.
    #

    def get_addresses(self, module_name=None):
        """
        Return coverage data for the named module as absolute addresses.

        If no name is given / available via self.modules, the trace is assumed
        to be a an ABSOLUTE ADDRESS TRACE.

        These are arugably the least flexible kind of traces available, but are
        still provided as an option. This fuction should return a list of
        integers representing absolute coverage addresses that match the open
        disassembler database...

          coverage_addresses = [address, address1, address2, ...]

        """
        raise NotImplementedError("Absolute addresses not supported by this log format")

    def get_offsets(self, module_name):
        """
        Return coverage data for the named module as relative offets.

        This function should return a list of integers representing the
        relative offset of an executed instruction OR basic block from the
        base of the requested module (module_name).

        It is *okay* to return an instruction trace, OR a basic block trace
        from thin function. Lighthoue will automatically detect basic block
        based traces and 'explode' them into instruction traces.

          coverage_data = [offset, offset2, offset3, ...]

        """
        raise NotImplementedError("Relative addresses not supported by this log format")

    def get_offset_blocks(self, module_name):
        """
        Return coverage data for the named module in block form.

        This function should return a list of tuples representing the coverage
        for the requested module (module_name). The tuples must be in the form
        of (offset, size).

          offset - a relative offset from the module_name base address
          size   - the size of the instruction, block, or sequence executed

        eg, if a basic block of 24 bytes in length at kernel32.dll+0x4182 was
        executed, its tuple would be (0x4182, 24).

        The complete list coverage data returned by thin function should be in
        the following form:

          coverage_data = [(offset, size), (offset1, size1), ...]

        """
        raise NotImplementedError("Block form not supported by this log format")
