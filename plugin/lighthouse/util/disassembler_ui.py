import functools

from .qt import *
from .misc import is_mainthread, mainthread
from .disassembler import *

#
# TODO: explain the reason for seperating off the disassembler UI
# TODO: this file is kind of a hodge-podge of crap
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
            if is_mainthread():
                return ff()
            else:
                return idaapi.execute_sync(ff, idaapi.MFF_FAST)

        # binja
        elif active_disassembler == platform.BINJA:

            if is_mainthread():
                return ff()
            else:
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

@mainthread
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

@mainthread
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

#------------------------------------------------------------------------------
# Global Waitbox
#------------------------------------------------------------------------------

g_waitbox = WaitBox("Please wait...")

def replace_wait_box(text):
    global g_waitbox
    g_waitbox.set_text(text)

def show_wait_box(text):
    global g_waitbox
    g_waitbox.set_text(text)
    g_waitbox.show()

def hide_wait_box():
    global g_waitbox
    g_waitbox.hide()

#------------------------------------------------------------------------------
# IDA Theme Prediction Code TODO
#------------------------------------------------------------------------------

def touch_ida_window(target):
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
    if using_ida7api:
        twidget = idaapi.get_current_widget()
        title = idaapi.get_widget_title(twidget)
    else:
        form = idaapi.get_current_tform()
        title = idaapi.get_tform_title(form)

    # touch/draw the widget by playing musical chairs
    if using_ida7api:

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

def get_ida_bg_color():
    """
    Get the background color of an IDA disassembly view.

    -----------------------------------------------------------------------

    The necessity of this function is pretty silly. I would like lighthouse
    to be color-aware of the user's IDA theme such that it selects reasonable
    colors that maintain readability.

    Since there is no supported way to probe the palette & colors in use by
    IDA, we must get creative. This function attempts to locate an IDA
    disassembly view, and take a screenshot of said widget. It will then
    attempt to extract the color of a single background pixel (hopefully).

    PS: please expose the get_graph_color(...) palette accessor, Ilfak ;_;
    """
    if using_ida7api:
        return get_ida_bg_color_ida7()
    else:
        return get_ida_bg_color_ida6()

def get_ida_bg_color_ida7():
    """
    Get the background color of an IDA disassembly view. (IDA 7+)
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
    touch_ida_window(twidget)

    # locate the Qt Widget for a form and take 1px image slice of it
    import sip
    widget = sip.wrapinstance(long(twidget), QtWidgets.QWidget)
    pixmap = widget.grab(QtCore.QRect(0, 10, widget.width(), 1))

    # convert the raw pixmap into an image (easier to interface with)
    image = QtGui.QImage(pixmap.toImage())

    # return the predicted background color
    return QtGui.QColor(predict_bg_color(image))

def get_ida_bg_color_ida6():
    """
    Get the background color of an IDA disassembly view. (IDA 6.x)
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
    touch_ida_window(form)

    # locate the Qt Widget for a form and take 1px image slice of it
    if using_pyqt5:
        widget = idaapi.PluginForm.FormToPyQtWidget(form)
        pixmap = widget.grab(QtCore.QRect(0, 10, widget.width(), 1))
    else:
        widget = idaapi.PluginForm.FormToPySideWidget(form)
        region = QtCore.QRect(0, 10, widget.width(), 1)
        pixmap = QtGui.QPixmap.grabWidget(widget, region)

    # convert the raw pixmap into an image (easier to interface with)
    image = QtGui.QImage(pixmap.toImage())

    # return the predicted background color
    return QtGui.QColor(predict_bg_color(image))

def predict_bg_color(image):
    """
    Predict the background color of an IDA View from a given image slice.

    We hypothesize that the 'background color' of a given image slice of an
    IDA form will be the color that appears in the longest 'streaks' or
    continuous sequences. This will probably be true 99% of the time.

    This function takes an image, and analyzes its first row of pixels. It
    will return the color that it believes to be the 'background color' based
    on its sequence length.

    TODO: we should probably move this
    """
    assert image.width() and image.height()

    # the details for the longest known color streak will be saved in these
    longest = 1
    speculative_bg = image.pixel(0, 0)

    # this will be the computed length of the current color streak
    sequence = 1

    # find the longest streak of color in a single pixel slice
    for x in xrange(1, image.width()):

        # the color of this pixel matches the last pixel, extend the streak count
        if image.pixel(x, 0) == image.pixel(x-1,0):
            sequence += 1

            #
            # this catches the case where the longest color streak is in fact
            # the last one. this ensures the streak color will get saved.
            #

            if x != image.width():
                continue

        # color change, determine if this was the longest continuous color streak
        if sequence > longest:

            # save the last pixel as the longest seqeuence / most likely BG color
            longest = sequence
            speculative_bg = image.pixel(x-1, 0)

            # reset the sequence counter
            sequence = 1

    # return the color we speculate to be the background color
    return speculative_bg
