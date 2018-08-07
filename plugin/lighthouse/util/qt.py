import time
import Queue
import logging

from .misc import is_mainthread
from .disassembler import disassembler

logger = logging.getLogger("Lighthouse.Qt")

# TODO/COMMENT: explain the global

qt_available = False

# TODO/COMMENT: update this
#------------------------------------------------------------------------------
# PyQt5 <--> PySide (Qt4) Interoperability
#------------------------------------------------------------------------------
#
#    As of IDA 6.9, IDA now uses PyQt5 instead PySide on Qt4.
#
#    From Qt4 --> Qt5, the organization of some of the code / objects has
#    changed. We use this file to shim/re-alias a few of these to reduce the
#    number of compatibility checks / code churn in the code that consumes them.
#
#    The 'using_pyqt5' global defined below is used to help us cut back
#    on compatibility checks in relevant UI code.
#

using_pyqt5 = False

#------------------------------------------------------------------------------
# PyQt5 Compatability
#------------------------------------------------------------------------------

if qt_available == False:
    try:
        import PyQt5.QtGui as QtGui
        import PyQt5.QtCore as QtCore
        import PyQt5.QtWidgets as QtWidgets

        # importing went okay, PyQt5 must be available for use
        qt_available = True
        using_pyqt5 = True

    # import failed, PyQt5 is not available
    except ImportError:
        pass

#------------------------------------------------------------------------------
# PySide Compatability
#------------------------------------------------------------------------------

if qt_available == False:
    try:
        import PySide.QtGui as QtGui
        import PySide.QtCore as QtCore

        # alias for less PySide <--> PyQt5 shimming
        QtWidgets = QtGui
        QtCore.pyqtSignal = QtCore.Signal
        QtCore.pyqtSlot = QtCore.Slot

        # importing went okay, PySide must be available for use
        qt_available = True

    # import failed, PySide is not available
    except ImportError:
        pass

#------------------------------------------------------------------------------
# UI Util
#------------------------------------------------------------------------------

def flush_qt_events():
    """
    Flush the Qt event pipeline.
    """
    qta = QtCore.QCoreApplication.instance()
    qta.processEvents()

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

#--------------------------------------------------------------------------
# Qt WaitBox
#--------------------------------------------------------------------------

class WaitBox(QtWidgets.QDialog):
    """
    A Generic WaitBox Dialog.
    """

    def __init__(self, text, title="Please wait...", abort=None):
        super(WaitBox, self).__init__()

        # dialog text & window title
        self._text = text
        self._title = title

        # abort routine (optional)
        self._abort = abort

        # initialize the dialog UI
        self._ui_init()

    def set_text(self, text):
        """
        Change the waitbox text.
        """
        self._text = text
        self._text_label.setText(text)
        qta = QtCore.QCoreApplication.instance()
        qta.processEvents()

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """
        self.setWindowFlags(
            self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint
        )
        self.setWindowFlags(
            self.windowFlags() | QtCore.Qt.MSWindowsFixedSizeDialogHint
        )
        self.setWindowFlags(
            self.windowFlags() & ~QtCore.Qt.WindowCloseButtonHint
        )

        # configure the main widget / form
        self.setSizeGripEnabled(False)
        self.setModal(True)
        self._dpi_scale = get_dpi_scale()

        # initialize abort button
        self._abort_button = QtWidgets.QPushButton("Cancel")

        # layout the populated UI just before showing it
        self._ui_layout()

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """
        self.setWindowTitle(self._title)
        self._text_label = QtWidgets.QLabel(self._text)
        self._text_label.setAlignment(QtCore.Qt.AlignHCenter)

        # vertical layout (whole widget)
        v_layout = QtWidgets.QVBoxLayout()
        v_layout.setAlignment(QtCore.Qt.AlignCenter)
        v_layout.addWidget(self._text_label)
        if self._abort:
            self._abort_button.clicked.connect(abort)
            v_layout.addWidget(self._abort_button)

        v_layout.setSpacing(self._dpi_scale*3)
        v_layout.setContentsMargins(
            self._dpi_scale*5,
            self._dpi_scale,
            self._dpi_scale*5,
            self._dpi_scale
        )

        # scale widget dimensions based on DPI
        height = self._dpi_scale * 15
        self.setMinimumHeight(height)

        # compute the dialog layout
        self.setLayout(v_layout)

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
