import abc

from ..qt import qt_available, QtGui

# TODO/COMMENT: update
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

#------------------------------------------------------------------------------
# Disassembler API
#------------------------------------------------------------------------------

class DisassemblerAPI(object):
    """
    TODO/COMMENT
    """
    __metaclass__ = abc.ABCMeta

    # the name of the disassembler framework / platform
    NAME = NotImplemented

    @abc.abstractmethod
    def __init__(self):
        self._waitbox = None

        if qt_available:
            from ..qt import WaitBox
            self._waitbox = WaitBox("Please wait...")

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

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

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    @abc.abstractmethod
    def get_database_directory(self):
        """
        Return the directory for the current database.
        """
        pass

    @abc.abstractmethod
    def get_disassembler_user_directory(self):
        """
        Return the 'user' directory for the disassembler.
        """
        pass

    @abc.abstractmethod
    def get_function_addresses(self):
        """
        Return all defined function addresses.
        """
        pass

    @abc.abstractmethod
    def get_function_name_at(self, address):
        """
        Return the name of the function at the given address.

        This is generally the user-facing/demangled name seen throughout the
        disassembler and is probably what you want to use for almost everything.
        """
        pass

    @abc.abstractmethod
    def get_function_raw_name_at(self, address):
        """
        Return the raw (eg, unmangled) name of the function at the given address.

        On the backend, most disassemblers store what is called the 'true' or
        'raw' (eg, unmangled) function name.
        """
        pass

    @abc.abstractmethod
    def get_imagebase(self):
        """
        Return the base address of the current database.
        """
        pass

    @abc.abstractmethod
    def get_root_filename(self):
        """
        Return the root executable (file) name used to generate the database.
        """
        pass

    @abc.abstractmethod
    def navigate(self, address):
        """
        Jump the disassembler UI to the given addreess.
        """
        pass

    @abc.abstractmethod
    def set_function_name_at(self, function_address, new_name):
        """
        Set the function name at given address.
        """
        pass

    #--------------------------------------------------------------------------
    # UI API Shims
    #--------------------------------------------------------------------------

    @abc.abstractmethod
    def get_disassembly_background_color(self):
        """
        Return the background color of the disassembly text view.
        """
        pass

    @abc.abstractmethod
    def is_msg_inited(self):
        """
        Is the disassembler ready to recieve messages to its output window?
        """
        pass

    @abc.abstractmethod
    def warning(self, text):
        """
        Display a warning dialog box with the given text.
        """
        pass

    #--------------------------------------------------------------------------
    # Synchronization Decorators
    #--------------------------------------------------------------------------

    @staticmethod
    def execute_read(function):
        """
        Thread-safe function decorator to read from the disassembler database.
        """
        pass

    @staticmethod
    def execute_ui(function):
        """
        Thread-safe function decorator to force mainthread execution.

        This is generally used for scheduling UI (Qt) events originating from
        a background thread.

        NOTE: Using this decorator waives your right to a return value.
        """
        pass

    #------------------------------------------------------------------------------
    # WaitBox API
    #------------------------------------------------------------------------------

    def show_wait_box(self, text):
        """
        Show the disassembler universal WaitBox.
        """
        assert qt_available, "This function can only be used in a Qt runtime"
        self._waitbox.set_text(text)
        self._waitbox.show()

    def hide_wait_box(self):
        """
        Hide the disassembler universal WaitBox.
        """
        assert qt_available, "This function can only be used in a Qt runtime"
        self._waitbox.hide()

    def replace_wait_box(self, text):
        """
        Replace the text in the disassembler universal WaitBox.
        """
        assert qt_available, "This function can only be used in a Qt runtime"
        self._waitbox.set_text(text)

    #------------------------------------------------------------------------------
    # Function Prefix API
    #------------------------------------------------------------------------------

    # TODO/COMMENT
    PREFIX_SEPARATOR = NotImplemented

    def prefix_function(self, function_address, prefix):
        """
        Prefix a function name with the given string.
        """
        original_name = self.get_function_raw_name_at(function_address)
        new_name = str(prefix) + self.PREFIX_SEPARATOR + str(original_name)

        # rename the function with the newly prefixed name
        self.set_function_name_at(function_address, new_name)

    def prefix_functions(self, function_addresses, prefix):
        """
        Prefix a list of functions with the given string.
        """
        for function_address in function_addresses:
            self.prefix_function(function_address, prefix)

    def clear_prefix(self, function_address):
        """
        Clear the prefix from a given function.
        """
        prefixed_name = self.get_function_raw_name_at(function_address)

        #
        # split the function name on the last prefix separator, saving
        # everything that comes after (eg, the original func name)
        #

        new_name = prefixed_name.rsplit(self.PREFIX_SEPARATOR)[-1]

        # the name doesn't appear to have had a prefix, nothing to do...
        if new_name == prefixed_name:
            return

        # rename the function with the prefix(s) now stripped
        self.set_function_name_at(function_address, new_name)

    def clear_prefixes(self, function_addresses):
        """
        Clear the prefix from a list of given functions.
        """
        for function_address in function_addresses:
            self.clear_prefix(function_address)

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
        """
        Install disassmbler-specific hooks necessary to capture rename events.
        """
        pass

    @abc.abstractmethod
    def unhook(self):
        """
        Remove disassmbler-specific hooks used to capture rename events.
        """
        pass

    def renamed(self, address, new_name):
        """
        This will be hooked by Lighthouse at runtime to capture rename events.
        """
        pass

#------------------------------------------------------------------------------
# Hooking
#------------------------------------------------------------------------------

class DockableShim(object):
    """
    TODO/COMMENT
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, window_title, icon_path):
        self._window_title = window_title
        self._window_icon = QtGui.QIcon(icon_path)
        self._widget = None

    def show(self):
        """
        Show the dockable widget.
        """
        self._widget.show()

    def hide(self):
        """
        Show the dockable widget.
        """
        self._widget.hide()

#------------------------------------------------------------------------------
# Utils
#------------------------------------------------------------------------------
#     Populate with disassmbler specific functions or helpers, as needed.

