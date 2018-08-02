from .disassembler import using_ida7api, using_pyqt5

# TODO: explain global

qt_available = False

#
# TODO: update commeet
# From Qt4 --> Qt5, the organization of some of the code / objects has
# changed. We use this file to shim/re-alias a few of these to reduce the
# number of compatibility checks / code churn in the code that consumes them.
#

try:

    if using_pyqt5:
        import PyQt5.QtGui as QtGui
        import PyQt5.QtCore as QtCore
        import PyQt5.QtWidgets as QtWidgets

    else:
        import PySide.QtGui as QtGui
        import PySide.QtCore as QtCore
        QtWidgets = QtGui
        QtCore.pyqtSignal = QtCore.Signal
        QtCore.pyqtSlot = QtCore.Slot

    # importing went okay, qt must be available for use
    qt_available = True

# import failed, PyQt5/PySide not available
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

def MonospaceFont():
    """
    Convenience alias for creating a monospace Qt font object.
    """
    font = QtGui.QFont("Monospace")
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
        self._dpi_scale = self.fontMetrics().averageCharWidth()
        m = self._dpi_scale

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
