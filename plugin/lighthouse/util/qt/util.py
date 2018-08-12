import time
import Queue
import logging

from .shim import *
from ..misc import is_mainthread
from ..disassembler import disassembler

logger = logging.getLogger("Lighthouse.Qt.Util")

# TODO/CLEANUP: this file is kind of a mess

#------------------------------------------------------------------------------
# Qt Util
#------------------------------------------------------------------------------

def get_qt_main_window():
    """
    Get the QMainWindow instance for the current Qt runtime.
    """
    app = QtCore.QCoreApplication.instance()
    return [x for x in app.allWidgets() if x.__class__ is QtWidgets.QMainWindow][0]

def flush_qt_events():
    """
    Flush the Qt event pipeline.
    """
    app = QtCore.QCoreApplication.instance()
    app.processEvents()

def get_dpi_scale():
    """
    Get a DPI-afflicted value useful for consistent UI scaling.
    """
    font = QtGui.QFont("Times", 15)
    return QtGui.QFontMetrics(font).xHeight()

def MonospaceFont(size=-1):
    """
    Convenience alias for creating a monospace Qt font object.
    """
    font = QtGui.QFont("Monospace", pointSize=size)
    font.setStyleHint(QtGui.QFont.TypeWriter)
    return font

def singleshot(ms, function=None):
    """
    A Qt Singleshot timer that can be stopped.
    """
    timer = QtCore.QTimer()
    timer.setInterval(ms)
    timer.setSingleShot(True)
    timer.timeout.connect(function)
    return timer

def remap_event(event, new_key):
    """
    Create an identical QKeyEvent, under a new key binding.
    """
    return QtGui.QKeyEvent(
        QtCore.QEvent.KeyPress,
        new_key,
        event.modifiers(),
        event.text(),
        event.isAutoRepeat(),
        event.count()
    )

def copy_to_clipboard(data):
    """
    Copy the given data (a string) to the user clipboard.
    """
    cb = QtWidgets.QApplication.clipboard()
    cb.clear(mode=cb.Clipboard)
    cb.setText(data, mode=cb.Clipboard)

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
        dpi_scale*80,
        dpi_scale*10
    )
    ok = dlg.exec_()
    text = str(dlg.textValue())
    return (ok, text)

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

#------------------------------------------------------------------------------
# IDA Async Magic
#------------------------------------------------------------------------------

def await_future(future):
    """
    This is effectively a technique I use to get around completely blocking
    IDA's mainthread while waiting for a threaded result that may need to make
    use of the execute_sync operators.

    Waiting for a 'future' thread result to come through via this function
    lets other execute_sync actions to slip through (at least Read, Fast).
    """
    interval = 0.02    # the interval which we wait for a response

    # run until the the future arrives
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

        if qt_available and is_mainthread():
            flush_qt_events()

def await_lock(lock):
    """
    Attempt to acquire a lock without blocking the IDA mainthread.

    See await_future() for more details.
    """

    elapsed  = 0       # total time elapsed waiting for the lock
    interval = 0.02    # the interval (in seconds) between acquire attempts
    timeout  = 60.0    # the total time allotted to acquiring the lock
    end_time = time.time() + timeout

    # wait until the the lock is available
    while time.time() < end_time:

        #
        # attempt to acquire the given lock without blocking (via 'False').
        # if we succesfully aquire the lock, then we can return (success)
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

        if qt_available and is_mainthread():
            flush_qt_events()

    #
    # we spent 60 seconds trying to acquire the lock, but never got it...
    # to avoid hanging IDA indefinitely (or worse), we abort via signal
    #

    raise RuntimeError("Failed to acquire lock after %f seconds!" % timeout)
