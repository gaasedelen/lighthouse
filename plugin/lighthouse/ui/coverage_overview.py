import os
import logging
import weakref

from lighthouse.util.qt import *
from lighthouse.util.misc import plugin_resource
from lighthouse.util.disassembler import disassembler, DockableWindow
from lighthouse.composer import ComposingShell
from lighthouse.ui.coverage_table import CoverageTableView, CoverageTableModel, CoverageTableController
from lighthouse.ui.coverage_combobox import CoverageComboBox
from lighthouse.ui.coverage_settings import TableSettingsMenu

logger = logging.getLogger("Lighthouse.UI.Overview")

#------------------------------------------------------------------------------
# Coverage Overview
#------------------------------------------------------------------------------

class CoverageOverview(DockableWindow):
    """
    The Coverage Overview Widget.
    """

    def __init__(self, core):
        super(CoverageOverview, self).__init__(
            "Coverage Overview",
            plugin_resource(os.path.join("icons", "overview.png"))
        )
        self._core = core
        self._visible = False

        # see the EventProxy class below for more details
        self._events = EventProxy(self)
        self._widget.installEventFilter(self._events)

        # initialize the plugin UI
        self._ui_init()

        # refresh the data UI such that it reflects the most recent data
        self.refresh()

    #--------------------------------------------------------------------------
    # Pseudo Widget Functions
    #--------------------------------------------------------------------------

    def show(self):
        """
        Show the CoverageOverview UI / widget.
        """
        self.refresh()
        super(CoverageOverview, self).show()
        self._visible = True

        #
        # if no metadata had been collected prior to showing the coverage
        # overview (eg, through loading coverage), we should do that now
        # before the user can interact with the view...
        #

        if not self._core.director.metadata.cached:
            self._table_controller.refresh_metadata()

    def terminate(self):
        """
        The CoverageOverview is being hidden / deleted.
        """
        self._visible = False
        self._combobox = None
        self._shell = None
        self._table_view = None
        self._table_controller = None
        self._table_model = None
        self._widget = None

    def isVisible(self):
        return self._visible

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """

        # initialize our ui elements
        self._ui_init_table()
        self._ui_init_toolbar()
        self._ui_init_signals()

        # layout the populated ui just before showing it
        self._ui_layout()

    def _ui_init_table(self):
        """
        Initialize the coverage table.
        """
        self._table_model = CoverageTableModel(self._core.director, self._widget)
        self._table_controller = CoverageTableController(self._table_model)
        self._table_view = CoverageTableView(
            self._table_controller,
            self._table_model,
            self._widget
        )

    def _ui_init_toolbar(self):
        """
        Initialize the coverage toolbar.
        """

        # initialize child elements to go on the toolbar
        self._ui_init_toolbar_elements()
        self._ui_init_settings()

        #
        # create the 'toolbar', and customize its style. specifically, we are
        # interested in tweaking the separator and padding between elements.
        #

        self._toolbar = QtWidgets.QToolBar()
        self._toolbar.setStyle(QtWidgets.QStyleFactory.create("Windows"))
        self._toolbar.setStyleSheet('QToolBar{padding:0;margin:0;}')

        # populate the toolbar with all our subordinates
        self._toolbar.addWidget(self._shell_elements)
        self._toolbar.addWidget(self._settings_button)

    def _ui_init_toolbar_elements(self):
        """
        Initialize the coverage toolbar UI elements.
        """

        # the composing shell
        self._shell = ComposingShell(
            self._core.director,
            weakref.proxy(self._table_model),
            weakref.proxy(self._table_view)
        )

        # the coverage combobox
        self._combobox = CoverageComboBox(self._core.director)

        # the splitter to make the shell / combobox resizable
        self._shell_elements = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self._shell_elements.setStyleSheet(
        """
        QSplitter::handle
        {
            background-color: #909090;
            width: 2px;
            height: 2px;
            margin: 0 0.5em 0 0.5em
        }

        QSplitter::handle:horizontal:hover
        {
            background-color: #3399FF;
        }
        """)

        # add the child items we wish to put the 'splitter' between
        # [ composing shell            ] [SPLITTER] [ combobox ]
        self._shell_elements.addWidget(self._shell)
        self._shell_elements.addWidget(self._combobox)

        # make the splitter responsive (animate) when hovered
        self._shell_elements.handle(1).setAttribute(QtCore.Qt.WA_Hover)

        # give the shell expansion preference over the combobox
        self._shell_elements.setStretchFactor(0, 1)

    def _ui_init_settings(self):
        """
        Initialize the overview settings popup.
        """

        # settings button
        self._settings_button = QtWidgets.QToolButton()
        self._settings_button.setIcon(get_qt_icon("SP_DialogResetButton"))
        self._settings_button.setStyleSheet("QToolButton::menu-indicator{image: none;}")

        # settings menu
        self._settings_menu = TableSettingsMenu(self._widget)

    def _ui_init_signals(self):
        """
        Connect UI signals.
        """
        self._settings_menu.connect_signals(self._table_controller, self._core)
        self._settings_button.clicked.connect(self._ui_show_settings)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """

        # layout the major elements of our widget
        layout = QtWidgets.QGridLayout()
        layout.setSpacing(get_dpi_scale()*5.0)
        layout.addWidget(self._table_view)
        layout.addWidget(self._toolbar)

        # apply the layout to the containing form
        self._widget.setLayout(layout)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_show_settings(self):
        """
        Handle a click of the settings button.
        """
        delta = QtCore.QPoint(
            -1*self._settings_menu.sizeHint().width(),
            -1*self._settings_menu.sizeHint().height()
        )
        center = QtCore.QPoint(
            self._settings_button.sizeHint().width()/2,
            self._settings_button.sizeHint().height()/2
        )
        where = self._settings_button.mapToGlobal(center+delta)
        self._settings_menu.popup(where)

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    @disassembler.execute_ui
    def refresh(self):
        """
        Refresh the Coverage Overview.
        """
        self._table_model.refresh()
        self._shell.refresh()
        self._combobox.refresh()

#------------------------------------------------------------------------------
# Qt Event Filter
#------------------------------------------------------------------------------

debugger_docked = False

class EventProxy(QtCore.QObject):

    def __init__(self, target):
        super(EventProxy, self).__init__()
        self._target = target

    def eventFilter(self, source, event):

        #
        # hook the destroy event of the coverage overview widget so that we can
        # cleanup after ourselves in the interest of stability
        #

        if int(event.type()) == 16: # NOTE/COMPAT: QtCore.QEvent.Destroy not in IDA7?
            self._target.terminate()

        #
        # this is an unknown event, but it seems to fire when the widget is
        # being saved/restored by a QMainWidget. we use this to try and ensure
        # the Coverage Overview stays docked when flipping between Reversing
        # and Debugging states in IDA.
        #
        # See issue #16 on github for more information.
        #

        if int(event.type()) == 2002 and disassembler.NAME == "IDA":
            import idaapi

            #
            # if the general registers IDA View exists, we make the assumption
            # that the user has probably started debugging.
            #

            # NOTE / COMPAT:
            if disassembler.USING_IDA7API:
                debug_mode = bool(idaapi.find_widget("General registers"))
            else:
                debug_mode = bool(idaapi.find_tform("General registers"))

            #
            # if this is the first time the user has started debugging, dock
            # the coverage overview in the debug QMainWidget workspace. its
            # dock status / position should persist future debugger launches.
            #

            global debugger_docked
            if debug_mode and not debugger_docked:
                idaapi.set_dock_pos(self._target._title, "Structures", idaapi.DP_TAB)
                debugger_docked = True

        return False
