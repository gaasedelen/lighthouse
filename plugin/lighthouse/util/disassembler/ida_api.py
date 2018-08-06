import functools

import idaapi
import idautils

from .api import DisassemblerAPI
from lighthouse.util.misc import is_mainthread

class IDAAPI(DisassemblerAPI):
    """
    TODO
    """
    NAME = "IDA"

    def __init__(self):
        self._init_version()

        #----------------------------------------------------------------------
        # IDA 7 API - COMPAT
        #----------------------------------------------------------------------
        #
        #    In IDA 7.0, Hex-Rays refactored the IDA API quite a bit. This
        #    impacts Lighthouse in a few places, so we use version checks at
        #    these junctions to determine which API's to use (v7.x or v6.x)
        #
        #    Search 'using_ida7api' in the codebase for example casese
        #

        self.using_ida7api = bool(self._version_major > 6)

    def _init_version(self):

        # retrieve IDA's version #
        disassembler_version = idaapi.get_kernel_version()
        major, minor = map(int, disassembler_version.split("."))

        # save the version number components for later use
        self._version_major = major
        self._version_minor = minor
        self._version_patch = 0

    #------------------------------------------------------------------------------
    # Properties
    #------------------------------------------------------------------------------

    @property
    def version_major(self):
        return self._version_major

    @property
    def version_minor(self):
        return self._version_minor

    @property
    def version_patch(self):
        return self._version_patch

    #------------------------------------------------------------------------------
    # API Shims
    #------------------------------------------------------------------------------

    def create_rename_hooks(self):
        if self.using_ida7api:
            class RenameHooks(idaapi.IDB_Hooks):
                pass
            return RenameHooks()
        else:
            class RenameHooks(idaapi.IDP_Hooks):
                pass
            return RenameHooks()

    def get_database_directory(self):
        return idautils.GetIdbDir()

    def get_disassembler_user_directory(self):
        return idaapi.get_user_idadir()

    def get_function_addresses(self):
        return list(idautils.Functions())

    def get_function_name_at(self, address):
        return idaapi.get_short_name(address)

    def get_imagebase(self):
        return idaapi.get_imagebase()

    def get_root_filename(self):
        return idaapi.get_root_filename()

    def is_msg_inited(self):
        return idaapi.is_msg_inited()

    def navigate(self, address):
        return idaapi.jumpto(address)

    @staticmethod
    def execute_read(function):
        """
        Modified from https://github.com/vrtadmin/FIRST-plugin-ida
        """

        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            output = [None]

            #
            # this inline function definition is technically what will execute
            # in the context of the main thread. we use this thunk to capture
            # any output the function may want to return to the user.
            #

            def thunk():
                output[0] = function(*args, **kwargs)
                return 1

            if is_mainthread():
                thunk()
            else:
                idaapi.execute_sync(thunk, idaapi.MFF_READ)

            # return the output of the synchronized execution / read
            return output[0]
        return wrapper

    @staticmethod
    def execute_ui(function):
        """
        Decorator to execute a function in the disassembler main thread.

        This is generally used for scheduling UI (Qt) events originating from
        a background thread.
        """

        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            ff = functools.partial(function, *args, **kwargs)

            # if we are already in the main (UI) thread, execute now
            if is_mainthread():
                return ff()

            # schedule the task to run in the main thread
            # TODO: this won't give us a real return value
            result = idaapi.execute_sync(ff, idaapi.MFF_FAST)
            return None

        return wrapper

