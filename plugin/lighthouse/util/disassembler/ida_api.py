import sys
import time
import logging
import binascii
import functools

import idaapi
import idautils

if int(idaapi.get_kernel_version()[0]) < 7:
    idaapi.warning("Lighthouse has deprecated support for IDA 6, please upgrade.")
    raise ImportError

from .api import DisassemblerCoreAPI, DisassemblerContextAPI
from ..qt import *
from ..misc import is_mainthread

logger = logging.getLogger("Lighthouse.API.IDA")

#------------------------------------------------------------------------------
# Utils
#------------------------------------------------------------------------------

def execute_sync(function, sync_type):
    """
    Synchronize with the disassembler for safe database access.

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
            idaapi.execute_sync(thunk, sync_type)

        # return the output of the synchronized execution
        return output[0]
    return wrapper

#------------------------------------------------------------------------------
# Disassembler Core API (universal)
#------------------------------------------------------------------------------

class IDACoreAPI(DisassemblerCoreAPI):
    """
    The IDA implementation of the disassembler API abstraction.
    """
    NAME = "IDA"

    def __init__(self):
        super(IDACoreAPI, self).__init__()
        self._dockable_factory = {}
        self._dockable_widgets = {}
        self._init_version()

    def _init_version(self):

        # retrieve IDA's version #
        disassembler_version = idaapi.get_kernel_version()
        major, minor = map(int, disassembler_version.split("."))

        # save the version number components for later use
        self._version_major = major
        self._version_minor = minor
        self._version_patch = 0

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def headless(self):
        return False

    #--------------------------------------------------------------------------
    # Synchronization Decorators
    #--------------------------------------------------------------------------

    @staticmethod
    def execute_read(function):
        return execute_sync(function, idaapi.MFF_READ)

    @staticmethod
    def execute_write(function):
        return execute_sync(function, idaapi.MFF_WRITE)

    @staticmethod
    def execute_ui(function):
        return execute_sync(function, idaapi.MFF_FAST)

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    def get_disassembler_user_directory(self):
        return idaapi.get_user_idadir()

    def get_disassembly_background_color(self):
        """
        Get the background color of the IDA disassembly view.

        Since there is no supported way to probe the palette & colors in use by
        IDA, we must get creative. This function attempts to locate an IDA
        disassembly view, and take a screenshot of said widget. It will then
        attempt to extract the color of a single background pixel (hopefully).
        """
        return self._get_ida_bg_color_ida7()

    def is_msg_inited(self):
        return idaapi.is_msg_inited()

    def warning(self, text):
        idaapi.warning(text)

    def message(self, message):
        print(message)

    #--------------------------------------------------------------------------
    # UI API Shims
    #--------------------------------------------------------------------------

    def register_dockable(self, dockable_name, create_widget_callback):
        self._dockable_factory[dockable_name] = create_widget_callback

    def create_dockable_widget(self, parent, dockable_name):
        import sip

        # create a dockable widget, and save a reference to it for later use
        twidget = idaapi.create_empty_widget(dockable_name)
        self._dockable_widgets[dockable_name] = twidget

        # cast the IDA 'twidget' as a Qt widget for use
        widget = sip.wrapinstance(int(twidget), QtWidgets.QWidget)
        widget.name = dockable_name
        widget.visible = False

        # return the dockable QtWidget / container
        return widget

    def show_dockable(self, dockable_name):
        try:
            make_dockable = self._dockable_factory[dockable_name]
        except KeyError:
            return False

        # TODO/IDA remove try/cacth after cleanup
        try:
            parent, dctx = None, None # not used for IDA's integration
            widget = make_dockable(dockable_name, parent, dctx)
        except Exception:
            logger.exception("Error showing dockable...")
            return False

        # get the original twidget, so we can use it with the IDA API's
        #twidget = idaapi.TWidget__from_ptrval__(widget) NOTE: IDA 7.2+ only...
        twidget = self._dockable_widgets.pop(dockable_name)
        if not twidget:
            self.warning("Could not open dockable window, because its reference is gone?!?")
            return

        # show the dockable widget
        flags = idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WOPN_RESTORE | idaapi.PluginForm.WOPN_PERSIST
        idaapi.display_widget(twidget, flags)
        widget.visible = True

        # attempt to 'dock' the widget in a reasonable location
        for target in ["IDA View-A", "Pseudocode-A"]:
            dwidget = idaapi.find_widget(target)
            if dwidget:
                idaapi.set_dock_pos(dockable_name, 'IDA View-A', idaapi.DP_RIGHT)
                break

    #--------------------------------------------------------------------------
    # Theme Prediction Helpers (Internal)
    #--------------------------------------------------------------------------

    def _get_ida_bg_color_ida7(self):
        """
        Get the background color of the IDA disassembly view. (IDA 7+)
        """
        return QtGui.QColor(0,0,0) # TODO/IDA
        names  = ["Enums", "Structures"]
        names += ["Hex View-%u" % i for i in range(5)]
        names += ["IDA View-%c" % chr(ord('A') + i) for i in range(5)]

        # find a form (eg, IDA view) to analyze colors from
        for window_name in names:
            twidget = idaapi.find_widget(window_name)
            if twidget:
                break
        else:
            raise RuntimeError("Failed to find donor view")

        # touch the target form so we know it is populated
        self._touch_ida_window(twidget)

        # locate the Qt Widget for a form and take 1px image slice of it
        import sip
        widget = sip.wrapinstance(int(twidget), QtWidgets.QWidget)
        pixmap = widget.grab(QtCore.QRect(0, 10, widget.width(), 1))

        # convert the raw pixmap into an image (easier to interface with)
        image = QtGui.QImage(pixmap.toImage())

        # return the predicted background color
        return QtGui.QColor(predict_bg_color(image))

    def _touch_ida_window(self, target):
        """
        Touch a window/widget/form to ensure it gets drawn by IDA.

        XXX/HACK:

          We need to ensure that widget we will analyze actually gets drawn
          so that there are colors for us to steal.

          To do this, we switch to it, and switch back. I tried a few different
          ways to trigger this from Qt, but could only trigger the full
          painting by going through the IDA routines.

        """

        # get the currently active widget/form title (the form itself seems transient...)
        twidget = idaapi.get_current_widget()
        title = idaapi.get_widget_title(twidget)

        # touch the target window by switching to it
        idaapi.activate_widget(target, True)
        flush_qt_events()

        # locate our previous selection
        previous_twidget = idaapi.find_widget(title)

        # return us to our previous selection
        idaapi.activate_widget(previous_twidget, True)
        flush_qt_events()

#------------------------------------------------------------------------------
# Disassembler Context API (database-specific)
#------------------------------------------------------------------------------

class IDAContextAPI(DisassemblerContextAPI):
    """
    TODO/COMMENT
    """

    def __init__(self, dctx):
        super(IDAContextAPI, self).__init__(dctx)

    @property
    def busy(self):
        return not(idaapi.auto_is_ok())

    #--------------------------------------------------------------------------
    # API Shims
    #--------------------------------------------------------------------------

    def get_current_address(self):
        return idaapi.get_screen_ea()

    def get_database_directory(self):
        return idautils.GetIdbDir()

    def get_function_addresses(self):
        return list(idautils.Functions())

    def get_function_name_at(self, address):
        return idaapi.get_short_name(address)

    def get_function_raw_name_at(self, function_address):
        return idaapi.get_name(function_address)

    def get_imagebase(self):
        return idaapi.get_imagebase()

    def get_root_filename(self):
        return idaapi.get_root_filename()

    def navigate(self, address):
        return idaapi.jumpto(address)

    def navigate_to_function(self, function_address, address):
        return self.navigate(function_address)

    def set_function_name_at(self, function_address, new_name):
        idaapi.set_name(function_address, new_name, idaapi.SN_NOWARN)

    #--------------------------------------------------------------------------
    # Hooks API
    #--------------------------------------------------------------------------

    def create_rename_hooks(self):
        return RenameHooks()

    #------------------------------------------------------------------------------
    # Function Prefix API
    #------------------------------------------------------------------------------

    PREFIX_SEPARATOR = "%"

#------------------------------------------------------------------------------
# Hooking
#------------------------------------------------------------------------------

class RenameHooks(idaapi.IDB_Hooks):

    def renamed(self, address, new_name, local_name):
        """
        Capture all IDA rename events.
        """

        # we should never care about local renames (eg, loc_40804b), ignore
        if local_name or new_name.startswith("loc_"):
            return 0

        # call the 'renamed' callback, that will get hooked by a listener
        self.name_changed(address, new_name)

        # must return 0 to keep IDA happy...
        return 0

    def name_changed(self, address, new_name):
        """
        A placeholder callback, which will get hooked / replaced once live.
        """
        pass

#------------------------------------------------------------------------------
# HexRays Util
#------------------------------------------------------------------------------

def map_line2citem(decompilation_text):
    """
    Map decompilation line numbers to citems.

    This function allows us to build a relationship between citems in the
    ctree and specific lines in the hexrays decompilation text.

    Output:

        +- line2citem:
        |    a map keyed with line numbers, holding sets of citem indexes
        |
        |      eg: { int(line_number): sets(citem_indexes), ... }
        '

    """
    line2citem = {}

    #
    # it turns out that citem indexes are actually stored inline with the
    # decompilation text output, hidden behind COLOR_ADDR tokens.
    #
    # here we pass each line of raw decompilation text to our crappy lexer,
    # extracting any COLOR_ADDR tokens as citem indexes
    #

    for line_number in xrange(decompilation_text.size()):
        line_text = decompilation_text[line_number].line
        line2citem[line_number] = lex_citem_indexes(line_text)
        #logger.debug("Line Text: %s" % binascii.hexlify(line_text))

    return line2citem

def map_line2node(cfunc, metadata, line2citem):
    """
    Map decompilation line numbers to node (basic blocks) addresses.

    This function allows us to build a relationship between graph nodes
    (basic blocks) and specific lines in the hexrays decompilation text.

    Output:

        +- line2node:
        |    a map keyed with line numbers, holding sets of node addresses
        |
        |      eg: { int(line_number): set(nodes), ... }
        '

    """
    line2node = {}
    treeitems = cfunc.treeitems
    function_address = cfunc.entry_ea

    #
    # prior to this function, a line2citem map was built to tell us which
    # citems reside on any given line of text in the decompilation output.
    #
    # now, we walk through this line2citem map one 'line_number' at a time in
    # an effort to resolve the set of graph nodes associated with its citems.
    #

    for line_number, citem_indexes in iteritems(line2citem):
        nodes = set()

        #
        # we are at the level of a single line (line_number). we now consume
        # its set of citems (citem_indexes) and attempt to identify explicit
        # graph nodes they claim to be sourced from (by their reported EA)
        #

        for index in citem_indexes:

            # get the code address of the given citem
            try:
                item = treeitems[index]
                address = item.ea

            # apparently this is a thing on IDA 6.95
            except IndexError as e:
                continue

            # find the graph node (eg, basic block) that generated this citem
            node = metadata.get_node(address)

            # address not mapped to a node... weird. continue to the next citem
            if not node:
                #logger.warning("Failed to map node to basic block")
                continue

            #
            # we made it this far, so we must have found a node that contains
            # this citem. save the computed node_id to the list of known
            # nodes we have associated with this line of text
            #

            nodes.add(node.address)

        #
        # finally, save the completed list of node ids as identified for this
        # line of decompilation text to the line2node map that we are building
        #

        line2node[line_number] = nodes

    # all done, return the computed map
    return line2node

def lex_citem_indexes(line):
    """
    Lex all ctree item indexes from a given line of text.

    The HexRays decompiler output contains invisible text tokens that can
    be used to attribute spans of text to the ctree items that produced them.

    This function will simply scrape and return a list of all the these
    tokens (COLOR_ADDR) which contain item indexes into the ctree.

    """
    i = 0
    indexes = []
    line_length = len(line)

    # lex COLOR_ADDR tokens from the line of text
    while i < line_length:

        # does this character mark the start of a new COLOR_* token?
        if line[i] == idaapi.COLOR_ON:

            # yes, so move past the COLOR_ON byte
            i += 1

            # is this sequence for a COLOR_ADDR?
            if ord(line[i]) == idaapi.COLOR_ADDR:

                # yes, so move past the COLOR_ADDR byte
                i += 1

                #
                # A COLOR_ADDR token is followed by either 8, or 16 characters
                # (a hex encoded number) that represents an address/pointer.
                # in this context, it is actually the index number of a citem
                #

                citem_index = int(line[i:i+idaapi.COLOR_ADDR_SIZE], 16)
                i += idaapi.COLOR_ADDR_SIZE

                # save the extracted citem index
                indexes.append(citem_index)

                # skip to the next iteration as i has moved
                continue

        # nothing we care about happened, keep lexing forward
        i += 1

    # return all the citem indexes extracted from this line of text
    return indexes

