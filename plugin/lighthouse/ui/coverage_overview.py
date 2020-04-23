import os
import logging
import weakref

from lighthouse.util.qt import *
from lighthouse.util.misc import plugin_resource
from lighthouse.util.disassembler import disassembler

from lighthouse.composer import ComposingShell
from lighthouse.ui.coverage_table import CoverageTableView, CoverageTableModel, CoverageTableController
from lighthouse.ui.coverage_combobox import CoverageComboBox
from lighthouse.ui.coverage_settings import TableSettingsMenu

logger = logging.getLogger("Lighthouse.UI.Overview")

#------------------------------------------------------------------------------
# Coverage Overview
#------------------------------------------------------------------------------

class CoverageOverview(object):
    """
    The Coverage Overview Widget.
    """

    def __init__(self, lctx, widget):
        self.lctx = lctx
        self.widget = widget
        self.director = self.lctx.director

        self.lctx.coverage_overview = self
        self.initialized = False

        # see the EventProxy class below for more details
        self._events = EventProxy(self)
        self.widget.installEventFilter(self._events)
        #    plugin_resource(os.path.join("icons", "overview.png"))

        # initialize the plugin UI
        self._ui_init()

        # refresh the data UI such that it reflects the most recent data
        self.refresh()

        # register for cues from the director
        self.director.refreshed(self.refresh)

    #--------------------------------------------------------------------------
    # Pseudo Widget Functions
    #--------------------------------------------------------------------------

    @property
    def name(self):
        if not self.widget:
            return "Coverage Overview"
        return self.widget.name

    @property
    def visible(self):
        if not self.widget:
            return False
        return self.widget.visible

    def terminate(self):
        """
        The CoverageOverview is being hidden / deleted.
        """
        self._combobox = None
        self._shell = None
        self._table_view = None
        self._table_controller = None
        self._table_model = None
        self.widget = None

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
        self._table_model = CoverageTableModel(self.lctx, self.widget)
        self._table_controller = CoverageTableController(self.lctx, self._table_model)
        self._table_view = CoverageTableView(self._table_controller, self._table_model, self.widget)

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
            self.lctx,
            weakref.proxy(self._table_model),
            weakref.proxy(self._table_view)
        )

        # the coverage combobox
        self._combobox = CoverageComboBox(self.director)

        # the splitter to make the shell / combobox resizable
        self._shell_elements = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self._shell_elements.setStyleSheet(
        """
        QSplitter
        {
            border: none;
        }

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
        self._settings_menu = TableSettingsMenu(self.widget)

    def _ui_init_signals(self):
        """
        Connect UI signals.
        """
        self._settings_menu.connect_signals(self._table_controller, self.lctx)
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
        self.widget.setLayout(layout)

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

    @disassembler.execute_ui
    def refresh_theme(self):
        """
        Update visual elements based on theme change.
        """
        self._table_view.refresh_theme()
        self._table_model.refresh_theme()
        self._shell.refresh_theme()
        self._combobox.refresh_theme()

#------------------------------------------------------------------------------
# Qt Event Filter
#------------------------------------------------------------------------------

debugger_docked = False

class EventProxy(QtCore.QObject):

    #
    # NOTE/COMPAT: QtCore.QEvent.Destroy not in IDA7? Just gonna ship our own...
    # - https://doc.qt.io/qt-5/qevent.html#Type-enum
    #

    EventShow = 17
    EventDestroy = 16
    EventLayoutRequest = 76
    EventUpdateLater = 78

    def __init__(self, target):
        super(EventProxy, self).__init__()
        self._target = weakref.proxy(target)
        self._first_hit = True

    def eventFilter(self, source, event):

        #
        # hook the destroy event of the coverage overview widget so that we can
        # cleanup after ourselves in the interest of stability
        #

        if int(event.type()) == self.EventDestroy:
            source.removeEventFilter(self)
            self._target.terminate()

        #
        # this seems to be 'roughly' the last event triggered after the widget
        # is done initializing in both IDA and Binja, but prior to the first
        # user-triggered 'show' events.
        #
        # this is mostly to account for the fact that binja 'shows' the widget
        # when it is initially created (outside of our control). this was
        # causing lighthouse to automatically cache database metadata when
        # every database was opened ...
        #

        elif int(event.type()) == self.EventLayoutRequest:
            self._target.initialized = True

        #
        # this is used to hook a little bit after the 'show' event of the
        # coverage overview. this is the most universal signal that the
        # user is *actually* trying to use lighthouse in a meaningful way...
        #
        # we will use this moment first to check if they skipped straight to
        # 'go' and opened the coverage overview without the metadata cache
        # getting built.
        #
        # this case should only happen if the user does 'Show Coverage
        # Overview' from the binja-controlled Window menu entry...
        #

        elif int(event.type()) == self.EventUpdateLater:

            if self._target.visible and self._first_hit:
                self._first_hit = False

                if disassembler.NAME == "BINJA":
                    self._target.lctx.start()

                if not self._target.director.metadata.cached:
                    self._target.director.refresh()

        #
        # this is an unknown event, but it seems to fire when the widget is
        # being saved/restored by a QMainWidget (in IDA). we use this to try
        # and ensure the Coverage Overview stays docked when flipping between
        # Reversing and Debugging states in IDA.
        #
        # See issue #16 on github for more information.
        #

        elif int(event.type()) == 2002 and disassembler.NAME == "IDA":
            import idaapi

            #
            # if the general registers IDA View exists, we make the assumption
            # that the user has probably started debugging.
            #

            debug_mode = bool(idaapi.find_widget("General registers"))

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
