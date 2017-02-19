import cProfile

import idaapi
import logging
from lighthouse.util import *

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
    COV_PERCENT:  "percent_instruction",
    FUNC_NAME:    "name",
    FUNC_ADDR:    "address",
    BASIC_BLOCKS: "node_count",
}

class CoverageModel(QtCore.QAbstractItemModel):
    """
    A Qt model interface to format coverage data for Qt views.
    """

    def __init__(self, db_coverage, parent=None):
        super(CoverageModel, self).__init__(parent)
        self._db_coverage = None

        # a map to correlate a given row in the table to the function coverage
        self.row2func = {}

        # green to red - 'light' theme
        #self._color_coverage_bad  = QtGui.QColor(207, 31, 0)
        #self._color_coverage_good = QtGui.QColor(75, 209, 42)

        # blue to red - 'dark' theme
        self._color_coverage_bad  = QtGui.QColor(221, 0, 0)
        self._color_coverage_good = QtGui.QColor(51, 153, 255)

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

        # update the model with the given coverage data
        self.update_model(db_coverage)

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

    def rowCount(self, index=QtCore.QModelIndex()):
        """
        Return the number of rows in the model. (The number of projects)
        """
        return len(self.row2func)

    def columnCount(self, index=QtCore.QModelIndex()):
        """
        Return the number of columns in the model. (The number of IDB fields)
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
        if not (0 <= index.row() < len(self.row2func)):
            return None

        # text alignment request
        if role == QtCore.Qt.TextAlignmentRole:

            # we want to align the first column left
            #if index.column() == 0:
            #    return QtCore.Qt.AlignVCenter

            # center align all other columns
            return QtCore.Qt.AlignCenter

        # data display request
        elif role == QtCore.Qt.DisplayRole:

            # lookup the func coverage object for this row
            func_coverage = self.row2func[index.row()]

            # Coverage % - (by instruction execution)
            if index.column() == COV_PERCENT:
                return "%.2f%%" % (func_coverage.percent_instruction*100)

            # Function Name
            elif index.column() == FUNC_NAME:
                return func_coverage.name

            # Function Address
            elif index.column() == FUNC_ADDR:
                return "0x%08X" % func_coverage.address

            # Basic Blocks
            elif index.column() == BASIC_BLOCKS:
                return "%u / %u" % (len(func_coverage.executed_nodes),
                                        func_coverage.node_count)

            # Branches
            elif index.column() == BRANCHES:
                return "TODO"

            # Lines
            elif index.column() == LINES:
                return "TODO"

        # cell background color request
        elif role == QtCore.Qt.BackgroundRole:
            func_coverage = self.row2func[index.row()]

            # TODO/PERF: can we just bake this in the func coverage?
            # compute cell/row color
            row_color = compute_color_on_gradiant(
                func_coverage.percent_instruction,
                self._color_coverage_bad,
                self._color_coverage_good
            )

            return row_color

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
            logger.error("TODO: implement column %u sorting" % column)
            return

        #
        # sort the existing entries in the table by the selected field name
        #
        # NOTE:
        #   using attrgetter appears to profile ~8-12% faster than lambdas
        #   accessing the member on the member, hence the strange paradigm
        #

        sorted_functions = sorted(
            self.row2func.itervalues(), # row2func has the 'existing' entries
            key=attrgetter(sort_field),
            reverse=sort_order
        )

        # finally, rebuild the row2func mapping
        self.row2func = dict(zip(xrange(len(sorted_functions)), sorted_functions))
        self.layoutChanged.emit()

        # save this as the most recent sort type
        self._last_sort = column
        self._last_sort_order = sort_order

    #--------------------------------------------------------------------------
    # Model Controls
    #--------------------------------------------------------------------------

    def hide_zero_coverage(self, hide=True):
        """
        Toggle zero coverage entries as visible.
        """
        if self._hide_zero == hide:
            return

        self._hide_zero = hide
        self._init_row2func_map()
        self.sort(self._last_sort, self._last_sort_order)
        self.layoutChanged.emit()

    def update_model(self, db_coverage):
        """
        Replace the underlying data source and re-generate model mappings.
        """
        self._db_coverage = db_coverage

        # initialize a new row2func map as the coverage data has changed
        self._init_row2func_map()

        # let consumers know that we have updated the model
        self.layoutChanged.emit()

    def _init_row2func_map(self):
        """
        Initialize the mapping to go from displayed row to function.
        """
        row = 0
        self.row2func = {}

        # no coverage, nothing else to do
        if not self._db_coverage:
            return

        functions = self._db_coverage.functions.itervalues()

        # only map items with a non-zero coverage as visible
        if self._hide_zero:
            for func_coverage in functions:
                if func_coverage.percent_instruction:
                    self.row2func[row] = func_coverage
                    row += 1

        # map all items as visible. faster to have this loop seperate from
        # the above so that we don't have to check a conditional every
        # iteration when not in use
        else:
            for func_coverage in self._db_coverage.functions.itervalues():
                self.row2func[row] = func_coverage
                row += 1

#------------------------------------------------------------------------------
# Coverage Overview
#------------------------------------------------------------------------------

class CoverageOverview(idaapi.PluginForm):
    """
    TODO
    """

    def __init__(self, db_coverage):
        super(CoverageOverview, self).__init__()
        self._title = "Coverage Overview"
        self._model = CoverageModel(db_coverage)

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

        #
        # coverage list table
        #

        self.table = QtWidgets.QTreeView()
        self.table.setRootIsDecorated(False)
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

        # checkbox to hide 0% coverage entries
        self.hide_zero_label    = QtWidgets.QLabel(" Hide 0% Coverage: ")
        self.hide_zero_checkbox = QtWidgets.QCheckBox()

        # populate the toolbar
        self.toolbar.addWidget(self.hide_zero_label)
        self.toolbar.addWidget(self.hide_zero_checkbox)

        #
        # ui signals
        #

        # connect a signal to jump to the function disas described by a row
        self.table.doubleClicked.connect(self._ui_entry_double_click)
        self.hide_zero_checkbox.stateChanged.connect(self._ui_hide_zero_toggle)
        #self.treeView.setContextMenuPolicy(Qt.CustomContextMenu)
        #self.treeView.customContextMenuRequested.connect(self.openMenu)

        #
        # ui layout
        #

        layout = QtWidgets.QGridLayout()
        layout.addWidget(self.table)
        layout.addWidget(self.toolbar)

        # install layout
        self.parent.setLayout(layout)

    def update_model(self, db_coverage):
        """
        Passthrough to update underlying model.
        """
        self._model.update_model(db_coverage)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_entry_double_click(self, index):
        """
        Handle double click event on the coverage table view.
        """

        # a double click on the table view will jump the user to the
        # clicked function in the disassembly view
        try:
            idaapi.jumpto(self._model.row2func[index.row()].address)
        except KeyError as e:
            pass

    def _ui_hide_zero_toggle(self, checked):
        """
        Handle state change of 'Hide 0% Coverage' checkbox.
        """
        self._model.hide_zero_coverage(checked)

#------------------------------------------------------------------------------
# Painting
#------------------------------------------------------------------------------

class GridDelegate(QtWidgets.QStyledItemDelegate):
    """
    Used solely to draw a grid in the CoverageOverview.
    """

    def __init__(self, parent=None):
        super(GridDelegate, self).__init__(parent)

    def paint(self, painter, option, index):
        super(GridDelegate, self).paint(painter, option, index)
        painter.save()
        painter.setPen(QtGui.QColor(QtCore.Qt.black))
        painter.drawRect(option.rect)
        painter.restore()

def compute_color_on_gradiant(percent, color1, color2):
    """
    Compute the color specified by a percent between two colors.
    """

    # dump the rgb values from QColor objects
    r1, g1, b1, _ = color1.getRgb()
    r2, g2, b2, _ = color2.getRgb()

    # compute the new color across the gradiant of color1 -> color 2
    r = r1 + percent * (r2 - r1)
    g = g1 + percent * (g2 - g1)
    b = b1 + percent * (b2 - b1)

    # return the new color
    return QtGui.QColor(r,g,b)
