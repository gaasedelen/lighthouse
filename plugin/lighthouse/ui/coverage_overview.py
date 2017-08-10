import string
import logging
import weakref
from operator import itemgetter, attrgetter

import idaapi

from lighthouse.util import *
from .coverage_combobox import CoverageComboBox
from lighthouse.composer import ComposingShell
from lighthouse.metadata import FunctionMetadata
from lighthouse.coverage import FunctionCoverage

logger = logging.getLogger("Lighthouse.UI.Overview")

#------------------------------------------------------------------------------
# Constants Defintion
#------------------------------------------------------------------------------

# declare named constants for coverage table column indexes
COV_PERCENT  = 0
FUNC_NAME    = 1
FUNC_ADDR    = 2
BLOCKS_HIT   = 3
INST_HIT     = 4
FUNC_SIZE    = 5
COMPLEXITY   = 6
FINAL_COLUMN = 7

# column -> field name mapping
COLUMN_TO_FIELD = \
{
    COV_PERCENT:  "instruction_percent",
    FUNC_NAME:    "name",
    FUNC_ADDR:    "address",
    BLOCKS_HIT:   "nodes_executed",
    INST_HIT:     "instructions_executed",
    FUNC_SIZE:    "size",
    COMPLEXITY:   "cyclomatic_complexity"
}

# column headers of the table
SAMPLE_CONTENTS = \
[
    " 100.00% ",
    " sub_140001B20 ",
    " 0x140001b20 ",
    " 100 / 100 ",
    " 1000 / 1000 ",
    " 10000000 ",
    " 1000000 "
]

#------------------------------------------------------------------------------
# Pseudo Widget Filter
#------------------------------------------------------------------------------

class EventProxy(QtCore.QObject):
    def __init__(self, target):
        super(EventProxy, self).__init__()
        self._target = target

    def eventFilter(self, source, event):
        if event.type() == QtCore.QEvent.Destroy:
            self._target.terminate()
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

        # internal
        self._director = director
        self._model = CoverageModel(director, self._widget)

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
        self._model = None
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
        self._ui_init_table()
        self._ui_init_toolbar()
        self._ui_init_signals()

        # layout the populated ui just before showing it
        self._ui_layout()

    def _ui_init_table(self):
        """
        Initialize the coverage table.
        """
        self._table = QtWidgets.QTableView()
        self._table.setFocusPolicy(QtCore.Qt.NoFocus)
        self._table.setStyleSheet(
            "QTableView { gridline-color: black; } " +
            "QTableView::item:selected { color: white; background-color: %s; } " % self._director._palette.selection.name()
        )

        # set these properties so the user can arbitrarily shrink the table
        self._table.setMinimumHeight(0)
        self._table.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Ignored
        )

        # install the underlying data source for the table
        self._table.setModel(self._model)

        # set the initial column widths for the table
        for i in xrange(len(SAMPLE_CONTENTS)):
            rect = self._font_metrics.boundingRect(SAMPLE_CONTENTS[i])
            self._table.setColumnWidth(i, rect.width())

        # table selection should be by row, not by cell
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # more code-friendly, readable aliases
        vh = self._table.verticalHeader()
        hh = self._table.horizontalHeader()

        # NOTE/COMPAT: set the row heights as fixed
        if using_pyqt5:
            vh.setSectionResizeMode(QtWidgets.QHeaderView.Fixed)
        else:
            vh.setResizeMode(QtWidgets.QHeaderView.Fixed)

        # specify the fixed row height in pixels
        vh.setDefaultSectionSize(int(self._font_metrics.height()))

        # hide the vertical header themselves as we don't need them
        vh.hide()

        # stretch the last column (which is blank)
        hh.setStretchLastSection(True)

        # disable bolding of table column headers when table is selected
        hh.setHighlightSections(False)

        # allow sorting of the table, and initialize the sort indicator
        self._table.setSortingEnabled(True)
        hh.setSortIndicator(FUNC_ADDR, QtCore.Qt.AscendingOrder)

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
        self._shell = ComposingShell(
            self._director,
            weakref.proxy(self._model),
            self._table
        )

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

        # jump to disassembly on table row double click
        self._table.doubleClicked.connect(self._ui_entry_double_click)

        # right click popup menu
        #self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        #self._table.customContextMenuRequested.connect(...)

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

    def _ui_entry_double_click(self, index):
        """
        Handle double click event on the coverage table view.

        A double click on the coverage table view will jump the user to
        the corresponding function in the IDA disassembly view.
        """
        idaapi.jumpto(self._model.row2func[index.row()])

    def _ui_hide_zero_toggle(self, checked):
        """
        Handle state change of 'Hide 0% Coverage' checkbox.
        """
        self._model.filter_zero_coverage(checked)

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    @idafast
    def refresh(self):
        """
        Refresh the Coverage Overview.
        """
        self._model.refresh()
        self._shell.refresh()
        self._combobox.refresh()

#------------------------------------------------------------------------------
# Coverage Table - TableModel
#------------------------------------------------------------------------------

class CoverageModel(QtCore.QAbstractTableModel):
    """
    A Qt model interface to format coverage data for Qt views.
    """

    def __init__(self, director, parent=None):
        super(CoverageModel, self).__init__(parent)
        self._blank_coverage = FunctionCoverage(idaapi.BADADDR)

        # the data source
        self._director = director

        # mapping to correlate a given row in the table to its function coverage
        self.row2func = {}
        self._row_count = 0

        # internal mappings of the explicit data / coverage we render
        self._no_coverage = []
        self._visible_metadata = {}
        self._visible_coverage = {}

        # column headers of the table
        self._column_headers = \
        {
            COV_PERCENT:  "Coverage %",
            FUNC_NAME:    "Function Name",
            FUNC_ADDR:    "Address",
            BLOCKS_HIT:   "Blocks Hit",
            INST_HIT:     "Instructions Hit",
            FUNC_SIZE:    "Function Size",
            COMPLEXITY:   "Complexity",
            FINAL_COLUMN: ""            # NOTE: stretch section, left blank for now
        }

        # initialize a monospace font to use with our widget(s)
        self._font = MonospaceFont()
        self._font_metrics = QtGui.QFontMetricsF(self._font)

        #----------------------------------------------------------------------
        # Sorting
        #----------------------------------------------------------------------

        # members to enlighten the model to its last known sort state
        self._last_sort = FUNC_ADDR
        self._last_sort_order = QtCore.Qt.AscendingOrder

        #----------------------------------------------------------------------
        # Filters
        #----------------------------------------------------------------------

        # OPTION: display 0% coverage entries
        self._hide_zero = False

        # OPTION: display functions matching search_string (substring)
        self._search_string = ""

        #----------------------------------------------------------------------
        # Signals
        #----------------------------------------------------------------------

        # register for cues from the director
        self._director.coverage_switched(self._internal_refresh)
        self._director.coverage_modified(self._internal_refresh)

    #--------------------------------------------------------------------------
    # AbstractItemModel Overloads
    #--------------------------------------------------------------------------

    def flags(self, index):
        return QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

    def rowCount(self, index=QtCore.QModelIndex()):
        """
        The number of table rows.
        """
        return self._row_count

    def columnCount(self, index=QtCore.QModelIndex()):
        """
        The number of table columns.
        """
        return len(self._column_headers)

    def headerData(self, column, orientation, role=QtCore.Qt.DisplayRole):
        """
        Define the properties of the the table rows & columns.
        """

        if orientation == QtCore.Qt.Horizontal:

            # the title of the header columns has been requested
            if role == QtCore.Qt.DisplayRole:
                try:
                    return self._column_headers[column]
                except KeyError as e:
                    pass

            # the text alignment of the header has beeen requested
            elif role == QtCore.Qt.TextAlignmentRole:

                # center align all columns
                return QtCore.Qt.AlignHCenter

        # unhandeled header request
        return None

    def data(self, index, role=QtCore.Qt.DisplayRole):
        """
        Define how Qt should access the underlying model data.
        """

        # data display request
        if role == QtCore.Qt.DisplayRole:

            # grab for speed
            column = index.column()

            # lookup the function info for this row
            function_address  = self.row2func[index.row()]
            function_metadata = self._director.metadata.functions[function_address]

            #
            # remember, if a function does *not* have coverage data, it will
            # not have an entry in the coverage map. that means we should
            # yield a default, 'blank', coverage item in these instances
            #

            function_coverage = self._director.coverage.functions.get(
                function_address,
                self._blank_coverage
            )

            # Coverage % - (by instruction execution)
            if column == COV_PERCENT:
                return "%5.2f%%" % (function_coverage.instruction_percent*100)

            # Function Name
            elif column == FUNC_NAME:
                return function_metadata.name

            # Function Address
            elif column == FUNC_ADDR:
                return "0x%X" % function_metadata.address

            # Basic Blocks
            elif column == BLOCKS_HIT:
                return "%3u / %-3u" % (function_coverage.nodes_executed,
                                       function_metadata.node_count)

            # Instructions Hit
            elif column == INST_HIT:
                return "%4u / %-4u" % (function_coverage.instructions_executed,
                                       function_metadata.instruction_count)

            # Function Size
            elif column == FUNC_SIZE:
                return "%u" % function_metadata.size

            # Cyclomatic Complexity
            elif column == COMPLEXITY:
                return "%u" % function_metadata.cyclomatic_complexity

        # cell background color request
        elif role == QtCore.Qt.BackgroundRole:
            function_address  = self.row2func[index.row()]
            function_coverage = self._director.coverage.functions.get(
                function_address,
                self._blank_coverage
            )
            return function_coverage.coverage_color

        # font color request
        elif role == QtCore.Qt.ForegroundRole:
            return QtGui.QColor(QtCore.Qt.white)

        # font format request
        elif role == QtCore.Qt.FontRole:
            return self._font

        # text alignment request
        elif role == QtCore.Qt.TextAlignmentRole:
            return QtCore.Qt.AlignCenter

        # unhandeled request, nothing to do
        return None

    #----------------------------------------------------------------------
    # Sorting
    #----------------------------------------------------------------------

    def sort(self, column, sort_order):
        """
        Sort coverage data model by column.
        """

        #
        # look up the name of field in the FunctionCoverage class object
        # that we would like to sort by based on the selected column
        #

        try:
            sort_field = COLUMN_TO_FIELD[column]

        # column has not been enlightened to sorting
        except KeyError as e:
            logger.warning("TODO: implement column %u sorting" % column)
            self.layoutChanged.emit()
            return

        #
        # NOTE: attrgetter appears to profile ~8-12% faster than lambdas
        #   accessing the member on the member, hence the strange paradigm
        #

        # sort the table entries by a function metadata attribute
        if column in [FUNC_NAME, FUNC_ADDR, FUNC_SIZE, COMPLEXITY]:
            sorted_functions = sorted(
                self._visible_metadata.itervalues(),
                key=attrgetter(sort_field),
                reverse=sort_order
            )

        # sort the table entries by a function coverage attribute
        elif column in [COV_PERCENT, BLOCKS_HIT, INST_HIT]:
            sorted_functions = sorted(
                self._visible_coverage.itervalues(),
                key=attrgetter(sort_field),
                reverse=sort_order
            )

            #
            # we sorted only the functions items that have known coverage.
            # but since some functions may not have had coverage, they were
            # not included in the sort.
            #
            # we simply append (or prepend) these unsortable (no coverage)
            # functions to the sorted list as they are still members of
            # the visible set regardless of their coverage status
            #

            #
            # if the sort was descending (100% --> 0%), the no_coverage
            # items (0%) should be appended to the *end*
            #

            if sort_order:
                sorted_functions += self._no_coverage

            #
            # if the sort was ascending (0% --> 100%), the no_coverage
            # items (0%) should be prepended to the *front*
            #

            else:
                sorted_functions = self._no_coverage + sorted_functions

        # create a generator of the sorted function addresses
        sorted_addresses = (x.address for x in sorted_functions)

        # finally, rebuild the row2func mapping and notify views of this change
        self.row2func = dict(zip(xrange(len(sorted_functions)), sorted_addresses))
        self.func2row = {v: k for k, v in self.row2func.iteritems()}
        self.layoutChanged.emit()

        # save the details of this sort event as they may be needed later
        self._last_sort = column
        self._last_sort_order = sort_order

    #--------------------------------------------------------------------------
    # Public
    #--------------------------------------------------------------------------

    def get_modeled_coverage_percent(self):
        """
        Get the coverage % represented by the current (visible) model.
        """
        sum_coverage = sum(cov.instruction_percent for cov in self._visible_coverage.itervalues())
        return (sum_coverage / (self._row_count or 1))*100

    #--------------------------------------------------------------------------
    # Filters
    #--------------------------------------------------------------------------

    def filter_zero_coverage(self, hide=True):
        """
        Filter out zero coverage functions from the model.
        """

        # the hide/unhide request matches the current state, ignore
        if self._hide_zero == hide:
            return

        # the filter is changing states, so we need to recompute the model
        self._hide_zero = hide
        self._internal_refresh()

    def filter_string(self, search_string):
        """
        Filter out functions whose names do not contain the given substring.
        """

        # the filter string matches the current string, ignore
        if search_string == self._search_string:
            return

        # the filter is changing states, so we need to recompute the model
        self._search_string = search_string
        self._internal_refresh()

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    def refresh(self):
        """
        Public refresh of the coverage model.
        """
        self._internal_refresh()

    @idafast
    def _internal_refresh(self):
        """
        Internal refresh of the coverage model.
        """
        self._refresh_data()

        # sort the data set according to the last selected sorted column
        self.sort(self._last_sort, self._last_sort_order)

    def _refresh_data(self):
        """
        Initialize the mapping to go from displayed row to function.
        """
        row = 0
        self.row2func = {}
        self.func2row = {}
        self._row_count = 0
        self._no_coverage = []
        self._visible_coverage = {}
        self._visible_metadata = {}

        metadata = self._director.metadata
        coverage = self._director.coverage

        #
        # if the search string is all lowercase, then we are going to perform
        # a case insensitive search/filter.
        #
        # that means we we want to 'normalize' all the function names by
        # making them lowercase before searching for our needle (search str)
        #

        normalize = lambda x: x
        if not (set(self._search_string) & set(string.ascii_uppercase)):
            normalize = lambda x: string.lower(x)

        #
        # it's time to rebuild the list of coverage items to make visible in
        # the coverage overview list. during this process, we filter out entries
        # that do not meet the criteria as specified by the user.
        #

        # loop through *all* the functions as defined in the active metadata
        for function_address in metadata.functions.iterkeys():

            #------------------------------------------------------------------
            # Filters - START
            #------------------------------------------------------------------

            # OPTION: ignore items with 0% coverage items
            if self._hide_zero and not function_address in coverage.functions:
                continue

            # OPTIONS: ignore items that do not match the search string
            if not self._search_string in normalize(metadata.functions[function_address].name):
                continue

            #------------------------------------------------------------------
            # Filters - END
            #------------------------------------------------------------------

            # store a reference to the listed function's metadata
            self._visible_metadata[function_address] = metadata.functions[function_address]

            # store a reference to the listed function's coverage
            if function_address in coverage.functions:
                self._visible_coverage[function_address] = coverage.functions[function_address]

            # reminder: coverage is *not* guaranteed :-)
            else:
                self._no_coverage.append(metadata.functions[function_address])

            # map the function address to a visible row # for easy lookup
            self.row2func[row] = function_address
            row += 1

        # build the inverse func --> row mapping
        self.func2row = {v: k for k, v in self.row2func.iteritems()}

        # bake the final number of rows into the model
        self._row_count = len(self.row2func)
