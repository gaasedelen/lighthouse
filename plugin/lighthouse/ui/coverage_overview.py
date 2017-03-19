import idaapi
import logging
from operator import itemgetter, attrgetter

from lighthouse.util import *
from lighthouse.composer import ComposingShell
from lighthouse.metadata import FunctionMetadata
from lighthouse.coverage import FunctionCoverage

logger = logging.getLogger("Lighthouse.UI.Overview")

#------------------------------------------------------------------------------
# Coverage Data Proxy Model
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

class CoverageModel(QtCore.QAbstractItemModel):
    """
    A Qt model interface to format coverage data for Qt views.
    """

    def __init__(self, parent=None):
        super(CoverageModel, self).__init__(parent)
        self._blank_coverage = FunctionCoverage(idaapi.BADADDR)

        # mapping to correlate a given row in the table to its function coverage
        self._rows = 0
        self.row2func = {}

        # internal references to the last known database metadata & coverage
        self._metadata = None
        self._coverage = None

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
            INST_HIT:     "Insttructions Hit",
            FUNC_SIZE:    "Function Size",
            FINAL_COLUMN: ""            # NOTE: stretch section, left blank for now
        }

        # initialize a monospace font to use with the table
        self._font = MonospaceFont()
        self._font_metrics = QtGui.QFontMetricsF(self._font)

        # members to enlighten the model to its last known sort state
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
            return self.createIndex(row, column, row)
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

        elif role == QtCore.Qt.FontRole:
            return self._font

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

        return True

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
        self._refresh()

    def update_model(self, metadata, coverage):
        """
        Replace the underlying data source and re-generate model mappings.
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
        self._no_coverage = []
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
                self._no_coverage.append(self._metadata.functions[function_address])

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

        # register for cues from the director
        self._director.coverage_switched(self._coverage_changed)
        self._director.coverage_modified(self._coverage_changed)

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """

        # initialize a monospace font for our ui elements to use
        self._font = MonospaceFont()
        self._font_metrics = QtGui.QFontMetricsF(self._font)

        # initialize our ui elements
        self._ui_init_table()
        self._ui_init_toolbar()
        self._ui_init_signals()

    def _ui_init_table(self):
        """
        Initialize the Coverage table UI elements.
        """
        self.table = QtWidgets.QTreeView()
        self.table.setRootIsDecorated(False)
        self.table.setUniformRowHeights(True)
        self.table.setExpandsOnDoubleClick(False)

        # set these properties so that we can arbitrarily shrink the table
        self.table.setMinimumHeight(0)
        self.table.setSizePolicy(QtWidgets.QSizePolicy.Ignored, QtWidgets.QSizePolicy.Ignored)

        # enable sorting on the table, default to sort by func address
        self.table.setSortingEnabled(True)
        self.table.header().setSortIndicator(FUNC_ADDR, QtCore.Qt.AscendingOrder)

        # install a drawing delegate to draw the grid lines on the list view
        delegate = GridDelegate(self.table)
        self.table.setItemDelegate(delegate)

        # install the data source for the list view
        self.table.setModel(self._model)

        # set initial column widths of the table
        for i in xrange(len(SAMPLE_CONTENTS)):
            rect = self._font_metrics.boundingRect(SAMPLE_CONTENTS[i])
            self.table.setColumnWidth(i, rect.width())

    def _ui_init_toolbar(self):
        """
        Initialize the Coverage toolbar UI elements.
        """

        #
        # initialize toolbar elements
        #

        # the composing shell
        self.shell = ComposingShell(self._director)

        # the loaded coverage combobox
        self.coverage_combobox = QtWidgets.QComboBox()
        self.coverage_combobox.setSizeAdjustPolicy(QtWidgets.QComboBox.AdjustToContentsOnFirstShow)
        self.coverage_combobox.setFont(self._font)

        # TODO
        coverage_list = QtWidgets.QListView()
        coverage_list.setItemDelegate(ComboBoxDelegate())

        # TODO
        self.coverage_combobox.setView(coverage_list)
        self.coverage_combobox.setStyleSheet(
        """
        QComboBox
        {
            padding: 0 0.5em 0 0.5em;
        }

        QComboBox QAbstractItemView
        {
            outline: none;
            padding: 0 0 2px 0;
        }
        """)
        self.coverage_combobox.setSizePolicy(QtWidgets.QSizePolicy.Ignored, QtWidgets.QSizePolicy.Ignored)

        # checkbox to hide 0% coverage entries
        self.hide_zero_label = QtWidgets.QLabel("Hide 0% Coverage: ")
        self.hide_zero_label.setFont(self._font)
        self.hide_zero_checkbox = QtWidgets.QCheckBox()

        #
        # populate the toolbar
        #

        self.toolbar = QtWidgets.QToolBar()

        #
        # customize the style of the bottom toolbar specifically, we are
        # interested in tweaking the seperator and item padding.
        #

        self.toolbar.setStyleSheet(
        """
        QToolBar::separator
        {
            background-color: #909090;
            width: 2px;
            margin: 0 0.5em 0 0.5em
        }
        """)

        self.splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.splitter.setStyleSheet(
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
        self.splitter.addWidget(self.shell)
        self.splitter.addWidget(self.coverage_combobox)
        self.splitter.handle(1).setAttribute(QtCore.Qt.WA_Hover)
        self.splitter.setStretchFactor(0, 1)

        # populate the toolbar with all our subordinates
        self.toolbar.addWidget(self.splitter)
        self.toolbar.addSeparator()
        self.toolbar.addWidget(self.hide_zero_label)
        self.toolbar.addWidget(self.hide_zero_checkbox)

    def _ui_init_signals(self):
        """
        Connect UI signals.
        """

        # jump to disassembly on table row double click
        self.table.doubleClicked.connect(self._ui_entry_double_click)

        # right click popup menu
        #self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        #self.table.customContextMenuRequested.connect(...)

        # composer combobox selection was changed
        self.coverage_combobox.activated[int].connect(self._ui_coverage_combobox_changed)

        # toggle 0% coverage checkbox
        self.hide_zero_checkbox.stateChanged.connect(self._ui_hide_zero_toggle)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """
        assert self.parent

        # layout the major elements of our widget
        layout = QtWidgets.QGridLayout()
        layout.addWidget(self.table)
        layout.addWidget(self.toolbar)

        # apply the widget layout
        self.parent.setLayout(layout)

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

    def _ui_coverage_combobox_changed(self, index):
        """
        Handle selection change of active coverage combobox.
        """
        coverage_name = self.coverage_combobox.itemData(index)
        self._director.select_coverage(coverage_name)

    def _ui_hide_zero_toggle(self, checked):
        """
        Handle state change of 'Hide 0% Coverage' checkbox.
        """
        self._model.hide_zero_coverage(checked)

    def _coverage_changed(self):
        """
        Handle a coverage (switched | modified) event from the director.
        """

        #
        # we only bother to act on an incoming director signal if the
        # coverage overview is actually visible. return now if hidden
        #

        if not self.parent.isVisible():
            return

        # refresh the coverage overview
        self.refresh()

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    def refresh(self):
        """
        TODO
        """
        self._model.update_model(self._director.metadata, self._director.coverage)
        self._ui_refresh_coverage_combobox()

    def _ui_refresh_coverage_combobox(self):
        """
        Refresh the active coverage combobox.
        """

        # clear the active coverage combobox
        self.coverage_combobox.clear()

        # add the special (eg 'Hot Shell', 'Aggregate') coverage names first
        for name in self._director.special_names:
            self.coverage_combobox.addItem(self._director.get_coverage_string(name), name)
            self.coverage_combobox.setItemData(self.coverage_combobox.count()-1, self._font, QtCore.Qt.FontRole)

        # add a seperator to distinguish the special versus normal coverage sets
        self.coverage_combobox.insertSeparator(self.coverage_combobox.count())

        # add the loaded/composed coverage names to the combobox
        for name in self._director.coverage_names:
            self.coverage_combobox.addItem(self._director.get_coverage_string(name), name)
            self.coverage_combobox.setItemData(self.coverage_combobox.count()-1, self._font, QtCore.Qt.FontRole)

        # finally, select the index matching the active coverage name
        new_index = self.coverage_combobox.findData(self._director.coverage_name)
        self.coverage_combobox.setCurrentIndex(new_index)

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

class ComboBoxDelegate(QtWidgets.QStyledItemDelegate):
    """
    Used solely to draw a seperator in the CoverageOverview combobox.
    """

    def __init__(self, parent=None):
        super(ComboBoxDelegate, self).__init__(parent)
        self.separator_color = QtGui.QColor(0x909090)
        self.padding = 2

    def sizeHint(self, option, index):
        if index.data(QtCore.Qt.AccessibleDescriptionRole) == "separator":
            return QtCore.QSize(1, 5)
        return super(ComboBoxDelegate, self).sizeHint(option, index)

    def paint(self, painter, option, index):

        # perform custom painting for the separator
        if index.data(QtCore.Qt.AccessibleDescriptionRole) == "separator":
            painter.setPen(self.separator_color)
            painter.drawLine(option.rect.left()+self.padding, option.rect.center().y(),
                             option.rect.right()-self.padding, option.rect.center().y())

        # perform standard painting for everything else
        else:
            super(ComboBoxDelegate, self).paint(painter, option, index)
