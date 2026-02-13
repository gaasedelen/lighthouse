
#
# this global is used to indicate whether Qt bindings for python are present
# and available for use by Lighthouse.
#

QT_AVAILABLE = False

#------------------------------------------------------------------------------
# PyQt5 <--> PySide2 Compatibility
#------------------------------------------------------------------------------
#
#    we use this file to shim/re-alias a few Qt API's to ensure compatibility
#    between the popular Qt frameworks. these shims serve to reduce the number
#    of compatibility checks in the plugin code that consumes them.
#
#    this file was critical for retaining compatibility with Qt4 frameworks
#    used by IDA 6.8/6.95, but it less important now. support for Qt 4 and
#    older versions of IDA (< 7.0) were deprecated in Lighthouse v0.9.0
#

USING_PYQT5 = False
USING_PYSIDE2 = False
USING_PYSIDE6 = False

#
#    TODO/QT: This file is getting pretty gross. this whole shim system
#    should probably get refactored as I really don't want disassembler
#    specific dependencies in here...
#

# IDA 9.2 SDK fix: migrate from PyQt5 to PySide6
# https://docs.hex-rays.com/user-guide/plugins/migrating-pyqt5-code-to-pyside6
try:
    import idaapi
    ver_major, ver_minor = map(int, idaapi.get_kernel_version().split("."))
    USING_NEW_IDA = ver_major == 9 and ver_minor >= 2
    USING_OLD_IDA = not(USING_NEW_IDA)
except ImportError:
    USING_NEW_IDA = False
    USING_OLD_IDA = False

try:
    import binaryninjaui
    USING_NEW_BINJA = "qt_major_version" in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6
    USING_OLD_BINJA = not(USING_NEW_BINJA)
except ImportError:
    USING_NEW_BINJA = False
    USING_OLD_BINJA = False

#------------------------------------------------------------------------------
# PyQt5 Compatibility
#------------------------------------------------------------------------------

# attempt to load PyQt5 (IDA from 7.0 to 9.1)
if USING_OLD_IDA:

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
# PySide2 Compatibility
#------------------------------------------------------------------------------

# if PyQt5 did not import, try to load PySide2 (Old Binary Ninja / Cutter)
if not QT_AVAILABLE and USING_OLD_BINJA:

    try:
        import PySide2.QtGui as QtGui
        import PySide2.QtCore as QtCore
        import PySide2.QtWidgets as QtWidgets

        # alias for less PySide2 <--> PyQt5 shimming
        QtCore.pyqtSignal = QtCore.Signal
        QtCore.pyqtSlot = QtCore.Slot

        # importing went okay, PySide must be available for use
        QT_AVAILABLE = True
        USING_PYSIDE2 = True

    # import failed. No Qt / UI bindings available...
    except ImportError:
        pass

#------------------------------------------------------------------------------
# PySide6 Compatibility
#------------------------------------------------------------------------------

# If all else fails, try to load PySide6 (New Binary Ninja and IDA)
if not QT_AVAILABLE and (USING_NEW_BINJA or USING_NEW_IDA):

    try:
        import PySide6.QtGui as QtGui
        import PySide6.QtCore as QtCore
        import PySide6.QtWidgets as QtWidgets

        # alias for less PySide6 <--> PyQt5 shimming
        QtCore.pyqtSignal = QtCore.Signal
        QtCore.pyqtSlot = QtCore.Slot
        QtWidgets.QAction = QtGui.QAction

        # importing went okay, PySide must be available for use
        QT_AVAILABLE = True
        USING_PYSIDE6 = True

    # import failed. No Qt / UI bindings available...
    except ImportError:
        pass
