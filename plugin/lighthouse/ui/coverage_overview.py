import os
import logging
import weakref

#from lighthouse.util import * # TODO: removee?
from lighthouse.util.qt import *
from lighthouse.util.misc import plugin_resource
from lighthouse.util.disassembler import disassembler, DockableWindow
from lighthouse.composer import ComposingShell
from lighthouse.ui.coverage_table import CoverageTableView, CoverageTableModel, CoverageTableController
from lighthouse.ui.coverage_combobox import CoverageComboBox

logger = logging.getLogger("Lighthouse.UI.Overview")

#------------------------------------------------------------------------------
# Coverage Overview
#------------------------------------------------------------------------------

class CoverageOverview(DockableWindow):
    """
    The Coverage Overview Widget.
    """

    def __init__(self, director):
        super(CoverageOverview, self).__init__(
            "Coverage Overview",
            plugin_resource(os.path.join("icons", "overview.png"))
        )

        # local reference to the director
        self._director = director

        # pseudo widget science
        self._visible = False
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
        self._widget.setMinimumWidth(0) # TODO/HACK: remove with table rework

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
        self._table_model = CoverageTableModel(self._director, self._widget)
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

        #
        # create the 'toolbar', and customize its style. specifically, we are
        # interested in tweaking the seperator and padding between elements.
        #

        self._toolbar = QtWidgets.QToolBar()
        self._toolbar.setStyleSheet(
        """
        QToolBar::separator
        {
            background-color: #909090;
            width: 2px;
            margin: 0 0.5em 0 0.5em
        }
        """)

        # populate the toolbar with all our subordinates
        self._toolbar.addWidget(self._shell_elements)
        self._toolbar.addSeparator()
        self._toolbar.addWidget(self._hide_zero_label)
        self._toolbar.addWidget(self._hide_zero_checkbox)

    def _ui_init_toolbar_elements(self):
        """
        Initialize the coverage toolbar UI elements.
        """

        # the composing shell
        self._shell = ComposingShell(
            self._director,
            weakref.proxy(self._table_model),
            weakref.proxy(self._table_view)
        )

        # the coverage combobox
        self._combobox = CoverageComboBox(self._director)

        # the checkbox to hide 0% coverage entries
        self._hide_zero_label = QtWidgets.QLabel("Hide 0% Coverage: ")
        self._hide_zero_label.setFont(MonospaceFont(9))
        self._hide_zero_checkbox = QtWidgets.QCheckBox()
        self._hide_zero_checkbox.setStyleSheet("QCheckBox{ padding-top: 1ex; }")

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

    def _ui_init_signals(self):
        """
        Connect UI signals.
        """
        self._hide_zero_checkbox.stateChanged.connect(self._ui_hide_zero_toggle)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """

        # layout the major elements of our widget
        layout = QtWidgets.QGridLayout()
        layout.addWidget(self._table_view)
        layout.addWidget(self._toolbar)

        # apply the layout to the containing form
        self._widget.setMinimumWidth(800) # TODO/HACK: remove with table rework
        self._widget.setLayout(layout)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_hide_zero_toggle(self, checked):
        """
        Handle state change of 'Hide 0% Coverage' checkbox.
        """
        self._table_model.filter_zero_coverage(checked)

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
# Pseudo Widget Filter
#------------------------------------------------------------------------------

debugger_docked = False

class EventProxy(QtCore.QObject):
    """
    TODO/COMMENT
    """

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
        # being saved/restored by a QMainWidget. We use this to try and ensure
        # the Coverage Overview stays docked when flipping between Reversing
        # and Debugging states in IDA.
        #
        # See issue #16 on github for more information.
        #

        if int(event.type()) == 2002:
            import idaapi

            #
            # if the general registers IDA View exists, we make the assumption
            # that the user has probably started debugging.
            #

            # NOTE / COMPAT:
            if disassembler.using_ida7api:
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
