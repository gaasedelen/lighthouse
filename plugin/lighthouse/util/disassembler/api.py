import abc

from ..qt import QT_AVAILABLE, QtGui

#------------------------------------------------------------------------------
# Disassembler API
#------------------------------------------------------------------------------
#
#    the purpose of this file is to provide an abstraction layer for the more
#    generic disassembler APIs required by the plugin codebase. we strive to
#    use (or extend) this API for the bulk of our disassembler operations,
#    making the plugin as disassembler-agnostic as possible.
#
#    by subclassing the templated classes below, the plugin can support other
#    disassembler plaforms relatively easily. at the moment, implementing these
#    subclasses is ~50% of the work that is required to add lighthouse support
#    to any given interactive disassembler.
#

class DisassemblerCoreAPI(object):
    """
    An abstract implementation of the required disassembler API.
    """
    __metaclass__ = abc.ABCMeta

    # the name of the disassembler framework, eg 'IDA' or 'BINJA'
    NAME = NotImplemented

    @abc.abstractmethod
    def __init__(self):
        self._ctxs = {}

        # required version fields
        self._version_major = NotImplemented
        self._version_minor = NotImplemented
        self._version_patch = NotImplemented

        if not self.headless and QT_AVAILABLE:
            from ..qt import WaitBox
            self._waitbox = WaitBox("Please wait...")
        else:
            self._waitbox = None

    def __delitem__(self, key):
        del self._ctxs[key]

    def __getitem__(self, key):
        return self._ctxs[key]

    def __setitem__(self, key, value):
        self._ctxs[key] = value

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    def version_major(self):
        """
        Return the major version number of the disassembler framework.
        """
        assert self._version_major != NotImplemented
        return self._version_major

    def version_minor(self):
        """
        Return the minor version number of the disassembler framework.
        """
        assert self._version_patch != NotImplemented
        return self._version_patch

    def version_patch(self):
        """
        Return the patch version number of the disassembler framework.
        """
        assert self._version_patch != NotImplemented
        return self._version_patch

    @abc.abstractproperty
    def headless(self):
        """
        Return a bool indicating if the disassembler is running without a GUI.
        """
        pass

    #--------------------------------------------------------------------------
    # Synchronization Decorators
    #--------------------------------------------------------------------------

    @staticmethod
    def execute_read(function):
        """
        Thread-safe function decorator to READ from the disassembler database.
        """
        raise NotImplementedError("execute_read() has not been implemented")

    @staticmethod
    def execute_write(function):
        """
        Thread-safe function decorator to WRITE to the disassembler database.
        """
        raise NotImplementedError("execute_write() has not been implemented")

    @staticmethod
    def execute_ui(function):
        """
        Thread-safe function decorator to perform UI disassembler actions.

        This function is generally used for executing UI (Qt) events from
        a background thread. as such, your implementation is expected to
        transfer execution to the main application thread where it is safe to
        perform Qt actions.
        """
        raise NotImplementedError("execute_ui() has not been implemented")

    #--------------------------------------------------------------------------
    # Disassembler Universal APIs
    #--------------------------------------------------------------------------

    @abc.abstractmethod
    def get_disassembler_user_directory(self):
        """
        Return the 'user' directory for the disassembler.
        """
        pass

    @abc.abstractmethod
    def get_disassembly_background_color(self):
        """
        Return the background color of the disassembly text view.
        """
        pass

    @abc.abstractmethod
    def is_msg_inited(self):
        """
        Return a bool if the disassembler output window is initialized.
        """
        pass

    @abc.abstractmethod
    def warning(self, text):
        """
        Display a warning dialog box with the given text.
        """
        pass

    @abc.abstractmethod
    def message(self, function_address, new_name):
        """
        Print a message to the disassembler console.
        """
        pass

    #--------------------------------------------------------------------------
    # UI APIs
    #--------------------------------------------------------------------------

    @abc.abstractmethod
    def register_dockable(self, dockable_name, create_widget_callback):
        """
        TODO/COMMENT
        """
        pass

    @abc.abstractmethod
    def create_dockable_widget(self, parent, dockable_name):
        """
        TODO/COMMENT
        """
        pass

    @abc.abstractmethod
    def show_dockable(self, dockable_name):
        """
        TODO/COMMENT
        """
        pass

    #------------------------------------------------------------------------------
    # WaitBox API
    #------------------------------------------------------------------------------

    def show_wait_box(self, text):
        """
        Show the disassembler universal WaitBox.
        """
        assert QT_AVAILABLE, "This function can only be used in a Qt runtime"
        self._waitbox.set_text(text)
        self._waitbox.show()

    def hide_wait_box(self):
        """
        Hide the disassembler universal WaitBox.
        """
        assert QT_AVAILABLE, "This function can only be used in a Qt runtime"
        self._waitbox.hide()

    def replace_wait_box(self, text):
        """
        Replace the text in the disassembler universal WaitBox.
        """
        assert QT_AVAILABLE, "This function can only be used in a Qt runtime"
        self._waitbox.set_text(text)

#------------------------------------------------------------------------------
# Disassembler Contextual API
#------------------------------------------------------------------------------

class DisassemblerContextAPI(object):
    """
    An abstract implementation of the required binary-specific disassembler API.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __init__(self, dctx):
        self.dctx = dctx

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @abc.abstractproperty
    def busy(self):
        """
        Return a bool indicating if the disassembler is busy / processing.
        """
        pass

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    @abc.abstractmethod
    def get_current_address(self):
        """
        Return the current cursor address in the open database.
        """
        pass

    @abc.abstractmethod
    def get_database_directory(self):
        """
        Return the directory for the open database.
        """
        pass

    @abc.abstractmethod
    def get_function_addresses(self):
        """
        Return all defined function addresses in the open database.
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
        Return the base address of the open database.
        """
        pass

    @abc.abstractmethod
    def get_root_filename(self):
        """
        Return the root executable (file) name used to generate the database.
        """
        pass

    @abc.abstractmethod
    def navigate(self, address, function_address=None):
        """
        Jump the disassembler UI to the given address.
        """
        pass

    @abc.abstractmethod
    def navigate_to_function(self, function_address, address):
        """
        Jump the disassembler UI to the given address, within a function.
        """
        pass

    @abc.abstractmethod
    def set_function_name_at(self, function_address, new_name):
        """
        Set the function name at given address.
        """
        pass

    #--------------------------------------------------------------------------
    # Hooks API
    #--------------------------------------------------------------------------

    @abc.abstractmethod
    def create_rename_hooks(self, function_address, new_name):
        """
        Returns a hooking object that can capture rename events for this context.
        """
        pass

    #--------------------------------------------------------------------------
    # Function Prefix API
    #--------------------------------------------------------------------------

    #
    # the following APIs are used to apply or clear prefixes to multiple
    # functions in the disassembly database. the only thing you're expected
    # to do here is select an appropriate PREFIX_SEPARATOR.
    #
    # your prefix separator is expected to be something unique, that a user
    # would probably *never* put into their function name themselves but
    # looks somewhat normal.
    #
    # in IDA, putting '%' in a function name appears as '_' in the function
    # list, so we use that as a prefix separator. in Binary Ninja, we use a
    # unicode character that looks like an underscore character.
    #
    # it is probably safe to steal the unicode char we use with binja for
    # your own implementation.
    #

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
    An abstract implementation of disassembler hooks to capture rename events.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def hook(self):
        """
        Install hooks into the disassembler that capture rename events.
        """
        pass

    @abc.abstractmethod
    def unhook(self):
        """
        Remove hooks used to capture rename events.
        """
        pass

    def renamed(self, address, new_name):
        """
        This will be hooked by Lighthouse at runtime to capture rename events.
        """
        pass
