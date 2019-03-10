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
    # Public
    #--------------------------------------------------------------------------

    def get_addresses(self, module_name=None):
        """
        Return coverage data for the named module as absolute addresses.
        """
        raise NotImplementedError("Absolute addresses not supported by this log format")

    def get_offsets(self, module_name=None):
        """
        Return coverage data for the named module as relative offets.
        """
        raise NotImplementedError("Relative addresses not supported by this log format")

    def get_blocks(self, module_name=None):
        """
        Return coverage data for the named module in block form (offset, size).
        """
        raise NotImplementedError("Block+Size not supported by this log format")

    #--------------------------------------------------------------------------
    # Parsing Routines - Top Level
    #--------------------------------------------------------------------------

    @abc.abstractmethod
    def _parse(self):
        raise NotImplementedError("Coverage parser not implemented")
