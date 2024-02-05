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
        self._action_change_theme = QtWidgets.QAction("Change theme", None)
        self._action_change_theme.setToolTip("Lighthouse color & theme customization")
        self.addAction(self._action_change_theme)
        self.addSeparator()

        # painting
        self._action_force_clear = QtWidgets.QAction("Force clear paint (slow!)", None)
        self._action_force_clear.setToolTip("Attempt to forcefully clear stuck paint from the database")
        self.addAction(self._action_force_clear)

        self._action_disable_paint = QtWidgets.QAction("Disable painting", None)
        self._action_disable_paint.setCheckable(True)
        self._action_disable_paint.setToolTip("Disable the coverage painting subsystem")
        self.addAction(self._action_disable_paint)
        self.addSeparator()

        # table actions
        self._action_refresh_metadata = QtWidgets.QAction("Rebuild coverage mappings", None)
        self._action_refresh_metadata.setToolTip("Refresh the database metadata and coverage mapping")
        self.addAction(self._action_refresh_metadata)

        self._action_export_html = QtWidgets.QAction("Generate HTML report", None)
        self._action_export_html.setToolTip("Export the coverage table to HTML")
        self.addAction(self._action_export_html)

        self._action_hide_zero = QtWidgets.QAction("Hide 0% coverage", None)
        self._action_hide_zero.setToolTip("Hide table entries with no coverage data")
        self._action_hide_zero.setCheckable(True)
        self.addAction(self._action_hide_zero)

    def connect_signals(self, controller, lctx):
        """
        Connect UI signals.
        """
        self._action_change_theme.triggered.connect(lctx.core.palette.interactive_change_theme)
        self._action_refresh_metadata.triggered.connect(lctx.director.refresh)
        self._action_hide_zero.triggered[bool].connect(controller._model.filter_zero_coverage)
        self._action_disable_paint.triggered[bool].connect(lambda x: lctx.painter.set_enabled(not x))
        self._action_force_clear.triggered.connect(lctx.painter.force_clear)
        self._action_export_html.triggered.connect(controller.export_to_html)
        lctx.painter.status_changed(self._ui_painter_changed_status)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    @disassembler.execute_ui
    def _ui_painter_changed_status(self, painter_enabled):
        """
        Handle an event from the painter being enabled/disabled.
        """
        self._action_disable_paint.setChecked(not painter_enabled)
