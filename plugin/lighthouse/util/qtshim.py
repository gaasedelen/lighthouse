import idaapi

#------------------------------------------------------------------------------
# Pyside --> PyQt5 - COMPAT
#------------------------------------------------------------------------------
#
#  NOTE:
#    As of IDA 6.9, Hex-Rays has started using PyQt5 versus PySide on Qt4.
#    This file tries to help us cut back from having as much compatibility
#    checks/churn by in every other file that consumes them.
#

def using_pyqt5():
    major, minor = map(int, idaapi.get_kernel_version().split("."))
    return (major == 6 and minor >= 9)

if using_pyqt5():
    import PyQt5.QtGui as QtGui
    import PyQt5.QtCore as QtCore
    import PyQt5.QtWidgets as QtWidgets

else:
    import PySide.QtGui as QtGui
    import PySide.QtCore as QtCore
    QtWidgets = None
