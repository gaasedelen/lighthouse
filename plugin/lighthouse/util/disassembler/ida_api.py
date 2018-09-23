import sys
import time
import logging
import binascii
import functools

import idaapi
import idautils

from .api import DisassemblerAPI, DockableShim
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
# Disassembler API
#------------------------------------------------------------------------------

class IDAAPI(DisassemblerAPI):
    """
    The IDA implementation of the disassembler API abstraction.
    """
    NAME = "IDA"

    #
    # in IDA 7.0, Hex-Rays refactored the IDA API quite a bit. This
    # impacts Lighthouse in a few places, so we use version checks at
    # these junctions to determine which API's to use (v7.x or v6.x)
    #
    # search 'USING_IDA7API' in the codebase for example cases
    #

    USING_IDA7API = bool(idaapi.IDA_SDK_VERSION >= 700)

    def __init__(self):
        super(IDAAPI, self).__init__()
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
    def version_major(self):
        return self._version_major

    @property
    def version_minor(self):
        return self._version_minor

    @property
    def version_patch(self):
        return self._version_patch

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

    def create_rename_hooks(self):
        if self.USING_IDA7API:
            class RenameHooks(idaapi.IDB_Hooks):
                pass
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

    def get_function_raw_name_at(self, function_address):
        if self.USING_IDA7API:
            return idaapi.get_name(function_address)
        return idaapi.get_true_name(idaapi.BADADDR, function_address)

    def get_imagebase(self):
        return idaapi.get_imagebase()

    def get_root_filename(self):
        return idaapi.get_root_filename()

    def navigate(self, address):
        return idaapi.jumpto(address)

    def set_function_name_at(self, function_address, new_name):
        idaapi.set_name(function_address, new_name, idaapi.SN_NOWARN)

    #--------------------------------------------------------------------------
    # UI API Shims
    #--------------------------------------------------------------------------

    def get_disassembly_background_color(self):
        """
        Get the background color of the IDA disassembly view.

        Since there is no supported way to probe the palette & colors in use by
        IDA, we must get creative. This function attempts to locate an IDA
        disassembly view, and take a screenshot of said widget. It will then
        attempt to extract the color of a single background pixel (hopefully).
        """
        if self.USING_IDA7API:
            return self._get_ida_bg_color_ida7()
        else:
            return self._get_ida_bg_color_ida6()

    def is_msg_inited(self):
        return idaapi.is_msg_inited()

    def warning(self, text):
        idaapi.warning(text)

    #------------------------------------------------------------------------------
    # Function Prefix API
    #------------------------------------------------------------------------------

    PREFIX_SEPARATOR = "%"

    #--------------------------------------------------------------------------
    # Theme Prediction Helpers (Internal)
    #--------------------------------------------------------------------------

    def _get_ida_bg_color_ida7(self):
        """
        Get the background color of the IDA disassembly view. (IDA 7+)
        """
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
        widget = sip.wrapinstance(long(twidget), QtWidgets.QWidget)
        pixmap = widget.grab(QtCore.QRect(0, 10, widget.width(), 1))

        # convert the raw pixmap into an image (easier to interface with)
        image = QtGui.QImage(pixmap.toImage())

        # return the predicted background color
        return QtGui.QColor(predict_bg_color(image))

    def _get_ida_bg_color_ida6(self):
        """
        Get the background color of the IDA disassembly view. (IDA 6.x)
        """
        names  = ["Enums", "Structures"]
        names += ["Hex View-%u" % i for i in range(5)]
        names += ["IDA View-%c" % chr(ord('A') + i) for i in range(5)]

        # find a form (eg, IDA view) to analyze colors from
        for window_name in names:
            form = idaapi.find_tform(window_name)
            if form:
                break
        else:
            raise RuntimeError("Failed to find donor View")

        # touch the target form so we know it is populated
        self._touch_ida_window(form)

        # locate the Qt Widget for a form and take 1px image slice of it
        if USING_PYQT5:
            widget = idaapi.PluginForm.FormToPyQtWidget(form, sys.modules[__name__])
            pixmap = widget.grab(QtCore.QRect(0, 10, widget.width(), 1))
        else:
            widget = idaapi.PluginForm.FormToPySideWidget(form, sys.modules[__name__])
            region = QtCore.QRect(0, 10, widget.width(), 1)
            pixmap = QtGui.QPixmap.grabWidget(widget, region)

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
        if self.USING_IDA7API:
            twidget = idaapi.get_current_widget()
            title = idaapi.get_widget_title(twidget)
        else:
            form = idaapi.get_current_tform()
            title = idaapi.get_tform_title(form)

        # touch/draw the widget by playing musical chairs
        if self.USING_IDA7API:

            # touch the target window by switching to it
            idaapi.activate_widget(target, True)
            flush_qt_events()

            # locate our previous selection
            previous_twidget = idaapi.find_widget(title)

            # return us to our previous selection
            idaapi.activate_widget(previous_twidget, True)
            flush_qt_events()

        else:

            # touch the target window by switching to it
            idaapi.switchto_tform(target, True)
            flush_qt_events()

            # locate our previous selection
            previous_form = idaapi.find_tform(title)

            # lookup our original form and switch back to it
            idaapi.switchto_tform(previous_form, True)
            flush_qt_events()

#------------------------------------------------------------------------------
# Dockable Window
#------------------------------------------------------------------------------

class DockableWindow(DockableShim):
    """
    A Dockable Qt widget, compatible with IDA 6.8 --> 7.x.
    """

    def __init__(self, window_title, icon_path):
        super(DockableWindow, self).__init__(window_title, icon_path)

        # IDA 7+ Widgets
        if IDAAPI.USING_IDA7API:
            import sip
            self._form = idaapi.create_empty_widget(self._window_title)
            self._widget = sip.wrapinstance(long(self._form), QtWidgets.QWidget)

        # legacy IDA PluginForm's
        else:
            self._form = idaapi.create_tform(self._window_title, None)
            if USING_PYQT5:
                self._widget = idaapi.PluginForm.FormToPyQtWidget(self._form, sys.modules[__name__])
            else:
                self._widget = idaapi.PluginForm.FormToPySideWidget(self._form, sys.modules[__name__])

        # set the window icon
        self._widget.setWindowIcon(self._window_icon)

    def show(self):
        """
        Show the dockable widget.
        """

        # IDA 7+ Widgets
        if IDAAPI.USING_IDA7API:
            flags = idaapi.PluginForm.WOPN_TAB     | \
                    idaapi.PluginForm.WOPN_MENU    | \
                    idaapi.PluginForm.WOPN_RESTORE | \
                    idaapi.PluginForm.WOPN_PERSIST
            idaapi.display_widget(self._form, flags)

        # legacy IDA PluginForm's
        else:
            flags = idaapi.PluginForm.FORM_TAB     | \
                    idaapi.PluginForm.FORM_MENU    | \
                    idaapi.PluginForm.FORM_RESTORE | \
                    idaapi.PluginForm.FORM_PERSIST | \
                    0x80 #idaapi.PluginForm.FORM_QWIDGET
            idaapi.open_tform(self._form, flags)

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

    for line_number, citem_indexes in line2citem.iteritems():
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

