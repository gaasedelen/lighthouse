import abc

#------------------------------------------------------------------------------
# Compatability File
#------------------------------------------------------------------------------
#
#    This file is used to reduce the number of compatibility checks made
#    throughout Lighthouse for varying versions of IDA.
#
#    As of July 2017, Lighthouse fully supports IDA 6.8 - 7.0. I expect that
#    much of this compatibility layer and IDA 6.x support will be dropped for
#    maintainability reasons sometime in 2018 as the userbase migrates up to
#    IDA 7.0 and beyond.
#

class DisassemblerAPI(object):
    """
    TODO/COMMENT
    """
    __metaclass__ = abc.ABCMeta

    # the name of the disassembler framework / platform
    NAME = NotImplemented

    #------------------------------------------------------------------------------
    # Properties
    #------------------------------------------------------------------------------

    @abc.abstractproperty
    def version_major(self):
        """
        Return the major version number of the disassembler framework.
        """
        pass

    @abc.abstractproperty
    def version_minor(self):
        """
        Return the minor version number of the disassembler framework.
        """
        pass

    @abc.abstractproperty
    def version_minor(self):
        """
        Return the patch version number of the disassembler framework.
        """
        pass

    #------------------------------------------------------------------------------
    # API Shims
    #------------------------------------------------------------------------------

    @abc.abstractmethod
    def get_database_directory():
        """
        Return the directory for the current database.
        """
        pass

    @abc.abstractmethod
    def get_disassembler_user_directory():
        """
        Return the 'user' directory for the disassembler.
        """
        pass

    @abc.abstractmethod
    def get_function_addresses():
        """
        Return all defined function addresses.
        """
        pass

    @abc.abstractmethod
    def get_function_name_at(address):
        """
        Return the name of the function at the given address.
        """
        pass

    @abc.abstractmethod
    def get_imagebase():
        """
        Return the base address of the current database.
        """
        pass

    @abc.abstractmethod
    def get_root_filename():
        """
        Return the root executable (file) name used to generate the database.
        """
        pass

    @abc.abstractmethod
    def is_msg_inited():
        """
        Is the disassembler ready to recieve messages to its output window?
        """
        pass

    @abc.abstractmethod
    def navigate(address):
        """
        Jump the disassembler UI to the given addreess.
        """
        pass

    #--------------------------------------------------------------------------
    # Synchronization Decorators
    #--------------------------------------------------------------------------

    @staticmethod
    def execute_read(address):
        """
        Thread-safe function decorator to read from the disassembler database.
        """
        pass

#------------------------------------------------------------------------------
# Hooking
#------------------------------------------------------------------------------

class RenameHooks(object):
    """
    TODO/COMMENT
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def hook(self):
        pass

    @abc.abstractmethod
    def unhook(self):
        pass

    def renamed(self, address, new_name, old_name):
        pass

