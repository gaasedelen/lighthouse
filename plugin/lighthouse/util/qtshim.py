import idaapi

#
# TODO
#

major, minor = map(int, idaapi.get_kernel_version().split("."))

# IDA 7 API compatibility
using_ida7api = (major > 6)
#using_pyqt5   = using_ida7api or (major == 6 and minor >= 9)

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
    return (major > 6) or (major == 6 and minor >= 9)

if using_pyqt5():
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
# Dockable Widget Shim
#------------------------------------------------------------------------------

class DockableShim(object):
    """
    A compatibility layer for dockable widgets (IDA 6.8 --> IDA 7.0)
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
            if using_pyqt5():
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
