import idaapi
import logging
from operator import itemgetter, attrgetter

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
FINAL_COLUMN = 7

# column -> field name mapping
COLUMN_TO_FIELD = \
{
    COV_PERCENT:  "instruction_percent",
    FUNC_NAME:    "name",
    FUNC_ADDR:    "address",
    BLOCKS_HIT:   "nodes_executed",
    INST_HIT:     "instructions_executed",
    FUNC_SIZE:    "size"
}

# column headers of the table
SAMPLE_CONTENTS = \
[
    " 100.00% ",
    " sub_140001B20 ",
    " 0x140001b20 ",
    " 100 / 100 ",
    " 1000 / 1000 ",
]

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
        self._model = CoverageModel(director)

        # initialize the plugin UI
        self._ui_init()

        # refresh the data UI such that it reflects the most recent data
        self.refresh()

    def show(self):
        """
        Show the CoverageOverview UI / widget.
        """
        self.refresh()
        super(CoverageOverview, self).show()

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
        self._table.setStyleSheet("QTableView { gridline-color: black; }")

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
        self._shell = ComposingShell(self._director)

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

        # register for cues from the director
        self._director.coverage_switched(self.refresh)
        self._director.coverage_modified(self.refresh)

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
        """

        #
        # a double click on the coverage table view will jump the user to
        # the corresponding function in the IDA disassembly view
        #

        idaapi.jumpto(self._model.row2func[index.row()])

    def _ui_hide_zero_toggle(self, checked):
        """
        Handle state change of 'Hide 0% Coverage' checkbox.
        """
        self._model.hide_zero_coverage(checked)

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
        self._rows = 0
        self.row2func = {}

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
            FINAL_COLUMN: ""            # NOTE: stretch section, left blank for now
        }

        # initialize a monospace font to use with our widget(s)
        self._font = MonospaceFont()
        self._font_metrics = QtGui.QFontMetricsF(self._font)

        # members to enlighten the model to its last known sort state
        self._last_sort = FUNC_ADDR
        self._last_sort_order = QtCore.Qt.AscendingOrder

        # used by the model to determine whether it should display 0% coverage entries
        self._hide_zero = False

        # TODO: list for director updates

    #--------------------------------------------------------------------------
    # AbstractItemModel Overloads
    #--------------------------------------------------------------------------

    def flags(self, index):
        return QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

    def rowCount(self, index=QtCore.QModelIndex()):
        """
        The number of table rows.
        """
        return self._rows

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

        if not index.isValid():
            return None

        # font format request
        if role == QtCore.Qt.FontRole:
            return self._font

        # text alignment request
        elif role == QtCore.Qt.TextAlignmentRole:
            return QtCore.Qt.AlignCenter

        # data display request
        elif role == QtCore.Qt.DisplayRole:

            # lookup the function metadata for this row
            function_address  = self.row2func[index.row()]
            function_metadata = self._visible_metadata[function_address]

            #
            # remember, if a function does *not* have coverage data, it will
            # not have an entry in the coverage map. that means we should
            # yield a default, 'blank', coverage item in these instances
            #

            function_coverage = self._visible_coverage.get(
                function_address,
                self._blank_coverage
            )

            # Coverage % - (by instruction execution)
            if index.column() == COV_PERCENT:
                return "%5.2f%%" % (function_coverage.instruction_percent*100)

            # Function Name
            elif index.column() == FUNC_NAME:
                return function_metadata.name

            # Function Address
            elif index.column() == FUNC_ADDR:
                return "0x%08X" % function_metadata.address

            # Basic Blocks
            elif index.column() == BLOCKS_HIT:
                return "%3u / %-3u" % (function_coverage.nodes_executed,
                                       function_metadata.node_count)

            # Instructions Hit
            elif index.column() == INST_HIT:
                return "%4u / %-4u" % (function_coverage.instructions_executed,
                                     function_metadata.instruction_count)

            # Function Size
            elif index.column() == FUNC_SIZE:
                return "%u" % function_metadata.size

        # cell background color request
        elif role == QtCore.Qt.BackgroundRole:
            function_address  = self.row2func[index.row()]
            function_coverage = self._visible_coverage.get(
                function_address,
                self._blank_coverage
            )
            return function_coverage.coverage_color

        # font color request
        elif role == QtCore.Qt.ForegroundRole:
            return QtGui.QColor(QtCore.Qt.white)

        # unhandeled request, nothing to do
        return None

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
        except KeyError as e:
            logger.warning("TODO: implement column %u sorting" % column)

            #
            # TODO/HACK:
            #
            #   This emit serves a rare case where sort is called via refresh()
            #   and the sort fails (we come through here). The completeness and
            #   correctness of the refresh() depends on sort() emitting a
            #   layoutChanged event.
            #
            #   We don't call layoutChanged from refresh() itself to avoid a
            #   possible double-emit... which can be costly in terms of time
            #   a refresh will take.
            #

            self.layoutChanged.emit()

            # bail
            return

        #
        # sort the existing entries in the table by the selected field name
        #

        #
        # NOTE:
        #   using attrgetter appears to profile ~8-12% faster than lambdas
        #   accessing the member on the member, hence the strange paradigm
        #

        # sort by a metric stored in the metadata
        if column in [FUNC_NAME, FUNC_ADDR, FUNC_SIZE]:
            sorted_functions = sorted(
                self._visible_metadata.itervalues(),
                key=attrgetter(sort_field),
                reverse=sort_order
            )

        # sort by a metric stored in the coverage
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

        # this should never be hit
        else:
            raise RuntimeError("WTF, Invalid sort column '%s'" % sort_field)

        # create a generator of the sorted function addresses
        sorted_addresses = (x.address for x in sorted_functions)

        # finally, rebuild the row2func mapping
        self.layoutAboutToBeChanged.emit()
        self.row2func = dict(zip(xrange(len(sorted_functions)), sorted_addresses))
        self.layoutChanged.emit()

        # save the details of this sort event as they may be needed later
        self._last_sort = column
        self._last_sort_order = sort_order

    #--------------------------------------------------------------------------
    # Model Controls
    #--------------------------------------------------------------------------

    def hide_zero_coverage(self, hide=True):
        """
        Toggle zero coverage entries as visible.
        """

        #
        # the request to hide or unhide the 0% coverage items matches the
        # current state, so there's nothing to do
        #

        if self._hide_zero == hide:
            return

        # the hide state is changing, so we need to recompute the model
        self._hide_zero = hide
        self.refresh()

    @idafast
    def refresh(self):
        """
        Internal refresh of the model.
        """

        # initialize a new row2func map as the coverage data has changed
        self._refresh_row2func_map()

        # sort the data set according to the last selected sorted column
        self.sort(self._last_sort, self._last_sort_order)

    def _refresh_row2func_map(self):
        """
        Initialize the mapping to go from displayed row to function.
        """
        row = 0
        self._rows = 0
        self.row2func = {}
        self._no_coverage = []
        self._visible_coverage = {}
        self._visible_metadata = {}

        metadata = self._director.metadata
        coverage = self._director.coverage

        #
        # it's time to rebuild the list of coverage items to make visible in
        # the coverage overview list. during this process, we filter out entries
        # that do not meet the criteria as specified by the user.
        #
        # NOTE: at this time, there is only one filtration option :P
        #

        # loop through *all* the functions as defined in the active metadata
        for function_address in metadata.functions.iterkeys():

            # OPTION: ignore items with 0% coverage items
            if self._hide_zero and not function_address in coverage.functions:
                continue

            #
            # TODO: make more filtration options!
            #

            #
            # ~ this entry has passed the overview filter, add it now ~
            #

            # store a reference to the listed function's metadata
            self._visible_metadata[function_address] = metadata.functions[function_address]

            # store a reference to the listed function's coverage
            try:
                self._visible_coverage[function_address] = coverage.functions[function_address]

            # reminder: coverage is *not* guaranteed :-)
            except KeyError as e:
                self._no_coverage.append(metadata.functions[function_address])

            # map the function address to a visible row # for easy lookup
            self.row2func[row] = function_address
            row += 1

        # bake the final number of rows into the model
        self._rows = len(self.row2func)
