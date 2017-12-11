import logging
import weakref

import idaapi

from lighthouse.util import *
from .coverage_combobox import CoverageComboBox
from .coverage_table import CoverageTable
from lighthouse.composer import ComposingShell

logger = logging.getLogger("Lighthouse.UI.Overview")

#------------------------------------------------------------------------------
# Pseudo Widget Filter
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
        # being saved/restored by a QMainWidget. We use this to try and ensure
        # the Coverage Overview stays docked when flipping between Reversing
        # and Debugging states in IDA.
        #
        # See issue #16 on github for more information.
        #

        if int(event.type()) == 2002:

            #
            # if the general registers IDA View exists, we make the assumption
            # that the user has probably started debugging.
            #

            # NOTE / COMPAT:
            if using_ida7api:
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

#------------------------------------------------------------------------------
# Coverage Overview
#------------------------------------------------------------------------------

class CoverageOverview(DockableShim):
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

    def terminate(self):
        """
        The CoverageOverview is being hidden / deleted.
        """
        self._visible = False
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

        # initialize a monospace font to use with our widget(s)
        self._font = MonospaceFont()
        self._font_metrics = QtGui.QFontMetricsF(self._font)

        # initialize our ui elements
        self._table = CoverageTable(self._director)
        self._ui_init_toolbar()
        self._ui_init_signals()

        # layout the populated ui just before showing it
        self._ui_layout()

    def _ui_init_toolbar(self):
        """
        Initialize the coverage toolbar.
        """

        # initialize toolbar elements
        self._ui_init_toolbar_elements()

        # populate the toolbar
        self._toolbar = QtWidgets.QToolBar()

        #
        # customize the style of the bottom toolbar specifically, we are
        # interested in tweaking the seperator and item padding.
        #

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
        self._toolbar.addWidget(self._splitter)
        self._toolbar.addSeparator()
        self._toolbar.addWidget(self._hide_zero_label)
        self._toolbar.addWidget(self._hide_zero_checkbox)

    def _ui_init_toolbar_elements(self):
        """
        Initialize the coverage toolbar UI elements.
        """

        # the composing shell
        self._shell = ComposingShell(self._director, self._table)

        # the coverage combobox
        self._combobox = CoverageComboBox(self._director)

        # the checkbox to hide 0% coverage entries
        self._hide_zero_label = QtWidgets.QLabel("Hide 0% Coverage: ")
        self._hide_zero_label.setFont(self._font)
        self._hide_zero_checkbox = QtWidgets.QCheckBox()

        # the splitter to make the shell / combobox resizable
        self._splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self._splitter.setStyleSheet(
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
        self._splitter.addWidget(self._shell)
        self._splitter.addWidget(self._combobox)

        # this makes the splitter responsive to hover events
        self._splitter.handle(1).setAttribute(QtCore.Qt.WA_Hover)

        # give the shell expansion preference over the combobox
        self._splitter.setStretchFactor(0, 1)

    def _ui_init_signals(self):
        """
        Connect UI signals.
        """

        # toggle 0% coverage checkbox
        self._hide_zero_checkbox.stateChanged.connect(self._ui_hide_zero_toggle)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """

        # layout the major elements of our widget
        layout = QtWidgets.QGridLayout()
        layout.addWidget(self._table)
        layout.addWidget(self._toolbar)

        # apply the layout to the containing form
        self._widget.setLayout(layout)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_hide_zero_toggle(self, checked):
        """
        Handle state change of 'Hide 0% Coverage' checkbox.
        """
        self._table.hide_zero_coverage(checked)

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    @idafast
    def refresh(self):
        """
        Refresh the Coverage Overview.
        """
        self._table.refresh()
        self._shell.refresh()
        self._combobox.refresh()

