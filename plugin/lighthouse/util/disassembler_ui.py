import functools

from .qt import *
from .ida import *
from .disassembler import *

#
# TODO: explain the reason for seperating off the disassembler UI
#

#------------------------------------------------------------------------------
# Disassembler Dependencies
#------------------------------------------------------------------------------

try:
    import idaapi
except ImportError:
    pass

try:
    import binaryninja
except ImportError:
    pass

#------------------------------------------------------------------------------
# Dockable Widget Shim (for IDA)
#------------------------------------------------------------------------------

def execute_ui(f):
    """
    Decorator to execute a function in the disassembler main thread.

    This is generally used for scheduling UI (Qt) events originating from
    a background thread.
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)

        # ida
        if active_disassembler == platform.IDA:
            if idaapi.is_main_thread():
                return ff()
            else:
                return idaapi.execute_sync(ff, idaapi.MFF_FAST)

        # binja
        elif active_disassembler == platform.BINJA:

            # TODO: is it possible to check if we are on the mainthread in binja?
            try:
                binaryninja.execute_on_main_thread(ff)
            except AttributeError: # XXX: binja bug, reported on 5/31/2018
                pass
            return None # TODO

        # unknown
        else:
            raise RuntimeError("Unknown disassembler! Cannot schedule UI execution!")

    return wrapper

#------------------------------------------------------------------------------
# Dockable Widget Shim (for IDA)
#------------------------------------------------------------------------------

class DockableShim(object):
    """
    A compatibility layer for dockable widgets (IDA 6.8 --> IDA 7.0)

    IDA 7.0 got rid of 'TForms' and instead only uses TWidgets (QWidgets),
    this class acts as a basic compatibility shim for IDA 6.8 --> IDA 7.0.
    """

    def __init__(self, title, icon_path):
        self._title = title
        self._icon = QtGui.QIcon(icon_path)

        # IDA 7+ Widgets
        if using_ida7api:
            import sip

            self._form   = idaapi.create_empty_widget(self._title)
            self._widget = sip.wrapinstance(long(self._form), QtWidgets.QWidget) # NOTE: LOL

        # legacy IDA PluginForm's
        else:
            self._form = idaapi.create_tform(self._title, None)
            if using_pyqt5:
                self._widget = idaapi.PluginForm.FormToPyQtWidget(self._form)
            else:
                self._widget = idaapi.PluginForm.FormToPySideWidget(self._form)

        self._widget.setWindowIcon(self._icon)

    def show(self):
        """
        Show the dockable widget.
        """

        # IDA 7+ Widgets
        if using_ida7api:
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
# Interactive
#------------------------------------------------------------------------------

#@mainthread # TODO: re-enable
def prompt_string(label, title, default=""):
    """
    Prompt the user with a dialog to enter a string.

    This does not block the IDA main thread (unlike idaapi.askstr)
    """
    dlg = QtWidgets.QInputDialog(None)
    dlg.setWindowFlags(dlg.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)
    dlg.setInputMode(QtWidgets.QInputDialog.TextInput)
    dlg.setLabelText(label)
    dlg.setWindowTitle(title)
    dlg.setTextValue(default)
    dlg.resize(
        dlg.fontMetrics().averageCharWidth()*80,
        dlg.fontMetrics().averageCharWidth()*10
    )
    ok = dlg.exec_()
    text = str(dlg.textValue())
    return (ok, text)

#@mainthread # TODO: re-enable
def gui_rename_function(function_address):
    """
    Interactive rename of a function in the IDB.
    """
    original_name = get_function_name(function_address)

    # prompt the user for a new function name
    ok, new_name = prompt_string(
        "Please enter function name",
        "Rename Function",
        original_name
       )

    #
    # if the user clicked cancel, or the name they entered
    # is identical to the original, there's nothing to do
    #

    if not (ok or new_name != original_name):
        return

    # rename the function
    idaapi.set_name(function_address, new_name, idaapi.SN_NOCHECK)

#@mainthread # TODO: re-enable
def gui_prefix_functions(function_addresses):
    """
    Interactive prefixing of functions in the IDB.
    """

    # prompt the user for a new function name
    ok, prefix = prompt_string(
        "Please enter a function prefix",
        "Prefix Function(s)",
        PREFIX_DEFAULT
       )

    # bail if the user clicked cancel or failed to enter a prefix
    if not (ok and prefix):
        return

    # prefix the given functions with the user specified prefix
    prefix_functions(function_addresses, prefix)
