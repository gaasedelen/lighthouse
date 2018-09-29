import sys
import time
import Queue
import logging

from .shim import *
from ..misc import is_mainthread
from ..disassembler import disassembler

logger = logging.getLogger("Lighthouse.Qt.Util")

#------------------------------------------------------------------------------
# Qt Fonts
#------------------------------------------------------------------------------

def MonospaceFont():
    """
    Convenience alias for creating a monospace Qt font object.
    """
    font = QtGui.QFont("Courier New")
    font.setStyleHint(QtGui.QFont.TypeWriter)
    return font

#------------------------------------------------------------------------------
# Qt Util
#------------------------------------------------------------------------------

def color_text(text, color):
    """
    Return a colorized (HTML) version of the given string.
    """
    return "<font color=\"%s\">%s</font>" % (color.name(), text)

def copy_to_clipboard(data):
    """
    Copy the given data (a string) to the system clipboard.
    """
    cb = QtWidgets.QApplication.clipboard()
    cb.clear(mode=cb.Clipboard)
    cb.setText(data, mode=cb.Clipboard)

def flush_qt_events():
    """
    Flush the Qt event pipeline.
    """
    app = QtCore.QCoreApplication.instance()
    app.processEvents()

def get_qt_icon(name):
    """
    Get a standard Qt icon by name.
    """
    icon_type = getattr(QtWidgets.QStyle, name)
    return QtWidgets.QApplication.style().standardIcon(icon_type)

def get_qt_main_window():
    """
    Get the QMainWindow instance for the current Qt runtime.
    """
    app = QtCore.QCoreApplication.instance()
    return [x for x in app.allWidgets() if x.__class__ is QtWidgets.QMainWindow][0]

def get_default_font_size():
    """
    Get the default font size for this QApplication.
    """
    return QtGui.QFont().pointSizeF()

def get_dpi_scale():
    """
    Get a DPI-afflicted value useful for consistent UI scaling.
    """
    font = MonospaceFont()
    font.setPointSize(normalize_to_dpi(120))
    fm = QtGui.QFontMetricsF(font)

    # xHeight is expected to be 40.0 at normal DPI
    return fm.height() / 173.0

def move_mouse_event(mouse_event, position):
    """
    Move the given mouse event to a different position.
    """
    new_event = QtGui.QMouseEvent(
        mouse_event.type(),
        position,
        mouse_event.button(),
        mouse_event.buttons(),
        mouse_event.modifiers()
    )
    return new_event

def normalize_to_dpi(font_size):
    """
    Normalize the given font size based on the system DPI.
    """
    if sys.platform == "darwin": # macos is lame
        return font_size + 3
    return font_size

def prompt_string(label, title, default=""):
    """
    Prompt the user with a dialog to enter a string.

    This does not block the IDA main thread (unlike idaapi.askstr)
    """
    dpi_scale = get_dpi_scale()
    dlg = QtWidgets.QInputDialog(None)
    dlg.setWindowFlags(dlg.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)
    dlg.setInputMode(QtWidgets.QInputDialog.TextInput)
    dlg.setLabelText(label)
    dlg.setWindowTitle(title)
    dlg.setTextValue(default)
    dlg.resize(
        dpi_scale*400,
        dpi_scale*50
    )
    ok = dlg.exec_()
    text = str(dlg.textValue())
    return (ok, text)

def predict_bg_color(image):
    """
    Predict the 'background color' of a given image.

    This function takes an image, and analyzes its first row of pixels. It
    will return the color that it believes to be the 'background color' based
    on the longest sequence of identical pixels.
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

            # save the last pixel as the longest sequence / most likely BG color
            longest = sequence
            speculative_bg = image.pixel(x-1, 0)

            # reset the sequence counter
            sequence = 1

    # return the color we speculate to be the background color
    return speculative_bg

def remap_key_event(event, new_key):
    """
    Change a given KeyPress QEvent to a different key.
    """
    return QtGui.QKeyEvent(
        QtCore.QEvent.KeyPress,
        new_key,
        event.modifiers(),
        event.text(),
        event.isAutoRepeat(),
        event.count()
    )

def singleshot(ms, function=None):
    """
    A Qt Singleshot timer that can be stopped.
    """
    timer = QtCore.QTimer()
    timer.setInterval(ms)
    timer.setSingleShot(True)
    timer.timeout.connect(function)
    return timer

#------------------------------------------------------------------------------
# Async Util
#------------------------------------------------------------------------------

def await_future(future):
    """
    Wait for a queue (future) message without blocking the main (Qt) thread.

    This is effectively a technique I use to get around completely blocking
    IDA's mainthread while waiting for a threaded result that may need to make
    use of the execute_sync operators.

    Waiting for a 'future' thread result to come through via this function
    lets other execute_sync actions to slip through (at least Read, Fast).
    """
    interval = 0.02    # the interval which we wait for a response

    # run until the message arrives through the future (a queue)
    while True:

        # block for a brief period to see if the future completes
        try:
            return future.get(timeout=interval)

        #
        # the future timed out, so perhaps it is blocked on a request
        # to the mainthread. flush the requests now and try again
        #

        except Queue.Empty as e:
            pass

        logger.debug("Awaiting future...")

        #
        # if we are executing (well, blocking) as the main thread, we need
        # to flush the event loop so IDA does not hang
        #

        if QT_AVAILABLE and is_mainthread():
            flush_qt_events()

def await_lock(lock):
    """
    Wait for a lock without blocking the main (Qt) thread.

    See await_future() for more details.
    """

    elapsed  = 0       # total time elapsed waiting for the lock
    interval = 0.02    # the interval (in seconds) between acquire attempts
    timeout  = 60.0    # the total time allotted to acquiring the lock
    end_time = time.time() + timeout

    # wait until the lock is available
    while time.time() < end_time:

        #
        # attempt to acquire the given lock without blocking (via 'False').
        # if we successfully acquire the lock, then we can return (success)
        #

        if lock.acquire(False):
            logger.debug("Acquired lock!")
            return

        #
        # the lock is not available yet. we need to sleep so we don't choke
        # the cpu, and try to acquire the lock again next time through...
        #

        logger.debug("Awaiting lock...")
        time.sleep(interval)

        #
        # if we are executing (well, blocking) as the main thread, we need
        # to flush the event loop so IDA does not hang
        #

        if QT_AVAILABLE and is_mainthread():
            flush_qt_events()

    #
    # we spent 60 seconds trying to acquire the lock, but never got it...
    # to avoid hanging IDA indefinitely (or worse), we abort via signal
    #

    raise RuntimeError("Failed to acquire lock after %f seconds!" % timeout)
