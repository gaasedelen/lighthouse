import logging
from lighthouse.util.qt import *
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.UI.Settings")

class TableSettingsMenu(QtWidgets.QMenu):
    """
    A quick-access settings menu for Lighthouse.
    """

    def __init__(self, parent=None):
        super(TableSettingsMenu, self).__init__(parent)
        self._visible_action = None
        self._ui_init_actions()

        if USING_PYQT5:
            self.setToolTipsVisible(True)

    #--------------------------------------------------------------------------
    # QMenu Overloads
    #--------------------------------------------------------------------------

    def event(self, event):
        """
        Hook the QMenu event stream.
        """
        action = self.activeAction()

        # swallow clicks to checkbox/radiobutton actions to keep qmenu open
        if event.type() == QtCore.QEvent.MouseButtonRelease:
            if action and action.isEnabled() and action.isCheckable():
                action.trigger()
                event.accept()
                return True

        # show action tooltips (for Qt < 5.1)
        elif event.type() == QtCore.QEvent.ToolTip and not USING_PYQT5:
            if action and self._visible_action != action:
                QtWidgets.QToolTip.showText(event.globalPos(), action.toolTip())
                self._visible_action = action
            event.accept()
            return True

        # clear tooltips (for Qt < 5.1)
        if not (action or USING_PYQT5):
            QtWidgets.QToolTip.hideText()
            self._visible_action = None

        # handle any other events as wee normally should
        return super(TableSettingsMenu, self).event(event)

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init_actions(self):
        """
        Initialize the menu actions.
        """

        # lighthouse colors
        self._action_colors = QtWidgets.QAction("Colors", None)
        self._action_colors.setToolTip("Lighthouse color & theme customization")
        #self.addAction(self._action_colors)
        #self.addSeparator()

        # painting
        self._action_pause_paint = QtWidgets.QAction("Pause painting", None)
        self._action_pause_paint.setCheckable(True)
        self._action_pause_paint.setToolTip("Disable coverage painting")
        self.addAction(self._action_pause_paint)

        # misc
        self._action_clear_paint = QtWidgets.QAction("Clear paint", None)
        self._action_clear_paint.setToolTip("Forcefully clear all paint")
        self.addAction(self._action_clear_paint)
        self.addSeparator()

        # table actions
        self._action_refresh_metadata = QtWidgets.QAction("Full table refresh", None)
        self._action_refresh_metadata.setToolTip("Refresh metadata & coverage for db")
        self.addAction(self._action_refresh_metadata)

        self._action_export_html = QtWidgets.QAction("Export to HTML", None)
        self._action_export_html.setToolTip("Export the coverage table to HTML")
        self.addAction(self._action_export_html)

        self._action_hide_zero = QtWidgets.QAction("Hide 0% coverage", None)
        self._action_hide_zero.setToolTip("Hide table entries with no coverage data")
        self._action_hide_zero.setCheckable(True)
        self.addAction(self._action_hide_zero)

    def connect_signals(self, controller, core):
        """
        Connect UI signals.
        """
        self._action_refresh_metadata.triggered.connect(controller.refresh_metadata)
        self._action_hide_zero.triggered[bool].connect(controller._model.filter_zero_coverage)
        self._action_pause_paint.triggered[bool].connect(lambda x: core.painter.set_enabled(not x))
        self._action_clear_paint.triggered.connect(core.painter.clear_paint)
        self._action_export_html.triggered.connect(controller.export_to_html)
        core.painter.status_changed(self._ui_painter_changed_status)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    @disassembler.execute_ui
    def _ui_painter_changed_status(self, painter_enabled):
        """
        Handle an event from the painter being enabled/disabled.
        """
        self._action_pause_paint.setChecked(not painter_enabled)
