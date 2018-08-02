from .disassembler import using_ida7api, using_pyqt5

#
# From Qt4 --> Qt5, the organization of some of the code / objects has
# changed. We use this file to shim/re-alias a few of these to reduce the
# number of compatibility checks / code churn in the code that consumes them.
#

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

#------------------------------------------------------------------------------
# UI Util
#------------------------------------------------------------------------------

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

