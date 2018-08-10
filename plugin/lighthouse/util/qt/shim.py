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

