
#
# this global is used to indicate whether Qt bindings for python are present
# and available for use by Lighthouse.
#

QT_AVAILABLE = False

#------------------------------------------------------------------------------
# PyQt5 <--> PySide (Qt4) Interoperability
#------------------------------------------------------------------------------
#
#    from Qt4 --> Qt5, a number of objects / modules have changed places
#    within the Qt codebase. we use this file to shim/re-alias a few of these
#    changes to reduce the number of compatibility checks / code churn in the
#    plugin code that consumes them.
#
#    this makes the plugin codebase compatible with both PySide & PyQt5, a
#    necessary requirement to maintain compatibility with IDA 6.8 --> 7.x
#
#    additionally, the 'USING_PYQT5' global can be used to check if we are
#    running in a PyQt5 context (versus PySide/Qt4). This may be used in a few
#    places throughout the project that could not be covered by our shims.
#

USING_PYQT5 = False

#------------------------------------------------------------------------------
# PyQt5 Compatibility
#------------------------------------------------------------------------------

# attempt to load PyQt5
if QT_AVAILABLE == False:
    try:
        import PyQt5.QtGui as QtGui
        import PyQt5.QtCore as QtCore
        import PyQt5.QtWidgets as QtWidgets

        # importing went okay, PyQt5 must be available for use
        QT_AVAILABLE = True
        USING_PYQT5 = True

    # import failed, PyQt5 is not available
    except ImportError:
        pass

#------------------------------------------------------------------------------
# PySide Compatibility
#------------------------------------------------------------------------------

# if PyQt5 did not import, try to load PySide
if QT_AVAILABLE == False:
    try:
        import PySide.QtGui as QtGui
        import PySide.QtCore as QtCore

        # alias for less PySide <--> PyQt5 shimming
        QtWidgets = QtGui
        QtCore.pyqtSignal = QtCore.Signal
        QtCore.pyqtSlot = QtCore.Slot

        # importing went okay, PySide must be available for use
        QT_AVAILABLE = True

    # import failed. No Qt / UI bindings available...
    except ImportError:
        pass

