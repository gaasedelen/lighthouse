import idaapi
import logging
from lighthouse.util import *
from lighthouse.metadata import FunctionMetadata
from lighthouse.coverage import FunctionCoverage

from operator import itemgetter, attrgetter

logger = logging.getLogger("Lighthouse.UI.Overview")

#------------------------------------------------------------------------------
# Coverage Data Proxy Model
#------------------------------------------------------------------------------

# declare named constants for coverage table column indexes
COV_PERCENT  = 0
FUNC_NAME    = 1
FUNC_ADDR    = 2
BASIC_BLOCKS = 3
BRANCHES     = 4
LINES        = 5
FINAL_COLUMN = 7

# column -> field name mapping
COLUMN_TO_FIELD = \
{
    COV_PERCENT:  "instruction_percent",
    FUNC_NAME:    "name",
    FUNC_ADDR:    "address",
    BASIC_BLOCKS: "node_count",
}

class CoverageModel(QtCore.QAbstractItemModel):
    """
    A Qt model interface to format coverage data for Qt views.
    """

    def __init__(self, parent=None):
        super(CoverageModel, self).__init__(parent)
        self._blank_coverage = FunctionCoverage(FunctionMetadata(idaapi.BADADDR)) # TODO: kinda dirty

        # a map to correlate a given row in the table to the function coverage
        self._rows = 0
        self.row2func = {}

        # TODO
        self._metadata = {}
        self._coverage = {}
        self._visible_metadata = {}
        self._visible_coverage = {}

        # headers of the table
        self._column_headers = \
        {
            COV_PERCENT:  "Coverage %",
            FUNC_NAME:    "Function Name",
            FUNC_ADDR:    "Address",
            BASIC_BLOCKS: "Basic Blocks",
            BRANCHES:     "Branches",
            LINES:        "Lines",
            FINAL_COLUMN: ""            # NOTE: stretch section, left blank for now
        }

        # used to make the model aware of its last sort state
        self._last_sort = FUNC_ADDR
        self._last_sort_order = QtCore.Qt.AscendingOrder

        # used by the model to determine whether it should display 0% coverage entries
        self._hide_zero = False

    #--------------------------------------------------------------------------
    # AbstractItemModel Overloads
    #--------------------------------------------------------------------------

    def flags(self, index):
        return QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

    def parent(self, index=QtCore.QModelIndex):
        return QtCore.QModelIndex()

    def index(self, row, column, parent=QtCore.QModelIndex()):
        try:
            return self.createIndex(row, column, self.row2func[row])
        except KeyError as e:
            return QtCore.QModelIndex()

    def canFetchMore(self, index):
        return True

    def rowCount(self, index=QtCore.QModelIndex()):
        """
        Return the number of rows in the model.
        """
        return self._rows

    def columnCount(self, index=QtCore.QModelIndex()):
        """
        Return the number of columns in the model.
        """
        return len(self._column_headers)

    def headerData(self, column, orientation, role=QtCore.Qt.DisplayRole):
        """
        Define the properties of how the table header should be displayed.
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

        # ensure the row requested exists
        if not (0 <= index.row() < self._rows):
            return None

        # text alignment request
        if role == QtCore.Qt.TextAlignmentRole:

            # center align all other columns
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
                return "%.2f%%" % (function_coverage.instruction_percent*100)

            # Function Name
            elif index.column() == FUNC_NAME:
                return function_metadata.name

            # Function Address
            elif index.column() == FUNC_ADDR:
                return "0x%08X" % function_metadata.address

            # Basic Blocks
            elif index.column() == BASIC_BLOCKS:
                return "%u / %u" % (function_coverage.nodes_executed,
                                    function_metadata.node_count)

            # Branches
            elif index.column() == BRANCHES:
                return "TODO"

            # Source Lines
            elif index.column() == LINES:
                return "TODO"

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
            return False

        #
        # sort the existing entries in the table by the selected field name
        #
        # NOTE:
        #   using attrgetter appears to profile ~8-12% faster than lambdas
        #   accessing the member on the member, hence the strange paradigm
        #

        # sort by a metric stored in the metadata
        if column in [FUNC_ADDR, FUNC_NAME, BASIC_BLOCKS]:
            sorted_functions = sorted(
                self._visible_metadata.itervalues(),
                key=attrgetter(sort_field),
                reverse=sort_order
            )

        # sort by a metric stored in the coverage
        elif column in [COV_PERCENT]:
            sorted_functions = sorted(
                self._visible_coverage.itervalues(),
                key=attrgetter(sort_field),
                reverse=sort_order
            )

        # this should never be hit
        else:
            raise RuntimeError("WTF, Invalid sort column '%s'" % sort_field)

        # create a generator of the sorted function addresses
        sorted_addresses = (x.address for x in sorted_functions)

        # finally, rebuild the row2func mapping
        self.layoutAboutToBeChanged.emit()
        self.row2func = dict(zip(xrange(len(sorted_functions)), sorted_addresses))
        self.layoutChanged.emit()

        # save this as the most recent sort type
        self._last_sort = column
        self._last_sort_order = sort_order
        return True

    #--------------------------------------------------------------------------
    # Model Controls
    #--------------------------------------------------------------------------

    def hide_zero_coverage(self, hide=True):
        """
        Toggle zero coverage entries as visible.
        """

        # state change matches current state, nothing to do
        if self._hide_zero == hide:
            return

        # rebuild the row map, using the new state (hide/unhide 0% items)
        self._hide_zero = hide
        self._refresh()

    def update_model(self, metadata, coverage):
        """
        Replace the underlying data source and re-generate model mappings.

        TODO: comment
        """
        self._metadata = metadata
        self._coverage = coverage
        self._refresh()

    def _refresh(self):
        """
        Internal refresh of the model.
        """

        # initialize a new row2func map as the coverage data has changed
        self._refresh_row2func_map()

        # sort the data set according to the last selected sorted column
        if not self.sort(self._last_sort, self._last_sort_order):

            #
            # if the sort was not successful (eg, unsupported column), then
            # emit the layout changed signal now to let consumers know that
            # we have updated the arrangement of model items
            #

            self.layoutChanged.emit()

    def _refresh_row2func_map(self):
        """
        Initialize the mapping to go from displayed row to function.
        """
        row = 0
        self.row2func = {}
        self._visible_coverage = {}
        self._visible_metadata = {}

        #
        # it's time to rebuild the list of coverage items to make visible in
        # the coverage overview list. during this process, we filter out entries
        # that do not meet the criteria as specified by the user.
        #
        # NOTE: at this time, there is only one filtration option :P
        #

        # loop through *all* the functions as defined in the active metadata
        for function_address in self._metadata.functions.iterkeys():

            # OPTION: ignore items with 0% coverage items
            if self._hide_zero and not function_address in self._coverage.functions:
                continue

            #
            # TODO: make more filtration options!
            #

            #
            # this entry has passed the overview filter, add it now
            #

            # store a reference to the listed function's metadata
            self._visible_metadata[function_address] = self._metadata.functions[function_address]

            # store a reference to the listed function's coverage
            try:
                self._visible_coverage[function_address] = self._coverage.functions[function_address]

            # reminder: coverage is *not* guaranteed :-)
            except KeyError as e:
                pass

            # map the function address to a visible row # for easy lookup
            self.row2func[row] = function_address
            row += 1

        # bake the final number of rows into the model
        self._rows = len(self.row2func)

#------------------------------------------------------------------------------
# Coverage Overview
#------------------------------------------------------------------------------

class CoverageOverview(idaapi.PluginForm):
    """
    The Coverage Overview Qt Widget.

    TODO
    """

    def __init__(self, director):
        super(CoverageOverview, self).__init__()
        self._title = "Coverage Overview"

        self._director = director
        self._model = CoverageModel()

        # initialize UI elements
        self._ui_init()

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """

        #
        # coverage list table
        #

        self.table = QtWidgets.QTreeView()
        self.table.setRootIsDecorated(False)
        self.table.setUniformRowHeights(True)
        self.table.setExpandsOnDoubleClick(False)

        # enable sorting on the table, default to sort by func address
        self.table.setSortingEnabled(True)
        self.table.header().setSortIndicator(FUNC_ADDR, QtCore.Qt.AscendingOrder)

        # install a drawing delegate to draw the grid lines on the list view
        delegate = GridDelegate(self.table)
        self.table.setItemDelegate(delegate)

        # install the data source for the list view
        self.table.setModel(self._model)

        #
        # coverage list toolbar (& members)
        #

        self.toolbar = QtWidgets.QToolBar()
        self.toolbar.setStyleSheet("QToolBar::separator { background-color: #909090; width: 2px; margin: 0 0.5em 0 0.5em }")

        # loaded coverage combobox
        self.active_coverage_label    = QtWidgets.QLabel("Active Coverage: ")
        self.active_coverage_combobox = QtGui.QComboBox()
        self.active_coverage_combobox.setStyleSheet("QComboBox { padding-left: 2ex; padding-right: 2ex; }")
        self.active_coverage_combobox.setSizeAdjustPolicy(QtGui.QComboBox.AdjustToContents)
        self.active_coverage_combobox.addItems(list(self._director.coverage_names))

        # checkbox to hide 0% coverage entries
        self.hide_zero_label    = QtWidgets.QLabel("Hide 0% Coverage: ")
        self.hide_zero_checkbox = QtWidgets.QCheckBox()

        # layout/populate the toolbar
        self.toolbar.addWidget(self.active_coverage_label)
        self.toolbar.addWidget(self.active_coverage_combobox)
        self.toolbar.addSeparator()
        self.toolbar.addWidget(self.hide_zero_label)
        self.toolbar.addWidget(self.hide_zero_checkbox)

        #
        # ui signals
        #

        # connect a signal to jump to the function disas described by a row
        self.table.doubleClicked.connect(self._ui_entry_double_click)
        #self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        #self.table.customContextMenuRequested.connect(...)
        self.active_coverage_combobox.activated[str].connect(self._ui_active_coverage_changed)
        self.hide_zero_checkbox.stateChanged.connect(self._ui_hide_zero_toggle)

    def _ui_layout(self):
        """
        Layout the major UI elements of the window.
        """
        assert self.parent

        # layout the major elements of our window
        layout = QtWidgets.QGridLayout()
        layout.addWidget(self.table)
        layout.addWidget(self.toolbar)

        # apply the widget layout to the window
        self.parent.setLayout(layout)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_entry_double_click(self, index):
        """
        Handle double click event on the coverage table view.
        """

        # a double click on the table view will jump the user to the clicked
        # function in the disassembly view
        try:
            idaapi.jumpto(self._model.row2func[index.row()])
        except KeyError as e:
            pass

    def _ui_active_coverage_changed(self, coverage_name):
        """
        Handle selection change of active coverage combobox.
        """
        print "got coverage changed signal"
        self._director.select_coverage(coverage_name)
        self.refresh()

    def _ui_hide_zero_toggle(self, checked):
        """
        Handle state change of 'Hide 0% Coverage' checkbox.
        """
        self._model.hide_zero_coverage(checked)

    #--------------------------------------------------------------------------
    # PluginForm Overloads
    #--------------------------------------------------------------------------

    def Show(self):
        """
        Show the dialog.
        """
        return super(CoverageOverview, self).Show(
            self._title,
            options=idaapi.PluginForm.FORM_PERSIST
        )

    def OnCreate(self, form):
        """
        Called when the view is created.
        """

        # NOTE/COMPAT
        if using_pyqt5():
            self.parent = self.FormToPyQtWidget(form)
        else:
            self.parent = self.FormToPySideWidget(form)

        # set window icon to the coverage overview icon
        self.parent.setWindowIcon(QtGui.QIcon(resource_file("icons\overview.png")))

        # layout the populated ui just before showing it
        self._ui_layout()

    #--------------------------------------------------------------------------
    # Controls
    #--------------------------------------------------------------------------

    def refresh(self):
        """
        TODO
        """
        self._model.update_model(self._director.metadata, self._director.coverage)
        self._ui_refresh_active_coverage_combobox()

    #--------------------------------------------------------------------------
    # Refresh Internals
    #--------------------------------------------------------------------------

    def _ui_refresh_active_coverage_combobox(self):
        """
        Refresh the active coverage combobox.
        """

        # clear the active coverage combobox
        self.active_coverage_combobox.clear()

        # re-populate the combobox with the latest coverage names
        new_items = list(self._director.coverage_names)
        self.active_coverage_combobox.addItems(new_items)

        # select the index with the correct coverage name as the 'active' coverage
        new_index = new_items.index(self._director.coverage_name)
        self.active_coverage_combobox.setCurrentIndex(new_index)

#------------------------------------------------------------------------------
# Painting
#------------------------------------------------------------------------------

class GridDelegate(QtWidgets.QStyledItemDelegate):
    """
    Used solely to draw a grid in the CoverageOverview.
    """

    def __init__(self, parent=None):
        super(GridDelegate, self).__init__(parent)
        self.grid_color = QtGui.QColor(QtCore.Qt.black)

    def paint(self, painter, option, index):
        super(GridDelegate, self).paint(painter, option, index)
        painter.save()
        painter.setPen(self.grid_color)
        painter.drawRect(option.rect)
        painter.restore()

