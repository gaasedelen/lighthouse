import string
import logging
from operator import itemgetter, attrgetter

from lighthouse.util import *
from lighthouse.coverage import FunctionCoverage

logger = logging.getLogger("Lighthouse.UI.Table")

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
# Coverage Table View
#------------------------------------------------------------------------------

class CoverageTable(QtWidgets.QTableView):
    """
    TODO
    """

    def __init__(self, director, parent=None):
        super(CoverageTable, self).__init__(parent)
        self.setObjectName(self.__class__.__name__)
        self._director = director

        # configure the widget for use
        self._ui_init()

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
        self.setFont(self._font)

        # install the underlying data model for the coverage table
        self._model = CoverageTableModel(self._director, self)
        self.setModel(self._model)

        # initialize our ui elements
        self._ui_init_table()
        self._ui_init_ctx_menu_actions()
        self._ui_init_signals()

    def _ui_init_table(self):
        """
        Initialize the coverage table.
        """
        palette = self._director._palette

        self.setFocusPolicy(QtCore.Qt.NoFocus)
        self.setStyleSheet(
        """
        QTableView
        {
            gridline-color: black;
            background-color: %s
        }

        QTableView::item:selected
        {
            color: white;
            background-color: %s;
        }
        """ % (palette.overview_bg.name(), palette.selection.name())
        )

        # set these properties so the user can arbitrarily shrink the table
        self.setMinimumHeight(0)
        self.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Ignored
        )

        # set the initial column widths for the table
        for i in xrange(len(SAMPLE_CONTENTS)):
            rect = self._font_metrics.boundingRect(SAMPLE_CONTENTS[i])
            self.setColumnWidth(i, rect.width())

        # table selection should be by row, not by cell
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # more code-friendly, readable aliases
        vh = self.verticalHeader()
        hh = self.horizontalHeader()

        # NOTE/COMPAT: set the row heights as fixed
        if using_pyqt5:
            vh.setSectionResizeMode(QtWidgets.QHeaderView.Fixed)
        else:
            vh.setResizeMode(QtWidgets.QHeaderView.Fixed)

        # specify the fixed row height in pixels
        vh.setDefaultSectionSize(int(self._font_metrics.height()))

        # hide the vertical table header as we don't have any use for them
        vh.hide()

        # stretch the last column (which is blank)
        hh.setStretchLastSection(True)

        # disable bolding of table column headers when table is selected
        hh.setHighlightSections(False)

        # allow sorting of the table, and initialize the sort indicator
        self.setSortingEnabled(True)
        hh.setSortIndicator(FUNC_ADDR, QtCore.Qt.AscendingOrder)

    def _ui_init_ctx_menu_actions(self):
        """
        Initialize the right click context menu actions.
        """

        # function actions
        self._action_rename = QtWidgets.QAction("Rename", None)
        self._action_copy_name = QtWidgets.QAction("Copy name", None)
        self._action_copy_address = QtWidgets.QAction("Copy address", None)
        self._action_copy_name_and_address = QtWidgets.QAction("Copy name and address", None)

        self._action_copy_names = QtWidgets.QAction("Copy names", None)
        self._action_copy_addresses = QtWidgets.QAction("Copy addresses", None)
        self._action_copy_names_and_addresses = QtWidgets.QAction("Copy names and addresses", None)

        # function prefixing actions
        self._action_prefix = QtWidgets.QAction("Prefix selected functions", None)
        self._action_clear_prefix = QtWidgets.QAction("Clear prefixes", None)

        # misc actions
        self._action_refresh_metadata = QtWidgets.QAction("Full refresh (slow)", None)

    def _ui_init_signals(self):
        """
        Connect UI signals.
        """

        # jump to disassembly on table row double click
        self.doubleClicked.connect(self._ui_entry_double_click)

        # right click popup menu
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._ui_ctx_menu_handler)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_entry_double_click(self, index):
        """
        Handle double click event on the coverage table.

        A double click on the coverage table view will jump the user to
        the corresponding function in the IDA disassembly view.
        """
        idaapi.jumpto(self._model.row2func[index.row()])

    def _ui_ctx_menu_handler(self, position):
        """
        Handle right click context menu event on the coverage table.
        """

        # create a right click menu based on the state and context
        ctx_menu = self._populate_ctx_menu()
        if not ctx_menu:
            return

        # show the popup menu to the user, and wait for their selection
        action = ctx_menu.exec_(self.viewport().mapToGlobal(position))

        # process the user action
        self._process_ctx_menu_action(action)

    #--------------------------------------------------------------------------
    # Context Menu
    #--------------------------------------------------------------------------

    def _populate_ctx_menu(self):
        """
        Populate a context menu for the table view based on selection.

        Returns a populated QMenu, or None.
        """

        # get the list rows currently selected in the coverage table
        selected_rows = self._table.selectionModel().selectedRows()
        if len(selected_rows) == 0:
            return None

        # the context menu we will dynamically populate
        ctx_menu = QtWidgets.QMenu()

        if len(selected_rows) == 1:
            # if there is only one table entry (a function) selected, then
            # show the menu actions available for a single function such as
            # copy function name, address, or renaming the function.
            ctx_menu.addAction(self._action_rename)
            ctx_menu.addAction(self._action_copy_name)
            ctx_menu.addAction(self._action_copy_address)
            ctx_menu.addAction(self._action_copy_name_and_address)
            ctx_menu.addSeparator()
        else:
            # if multiple functions are selected then show actions  available
            # for multiple functions.
            ctx_menu.addAction(self._action_copy_names)
            ctx_menu.addAction(self._action_copy_addresses)
            ctx_menu.addAction(self._action_copy_names_and_addresses)
            ctx_menu.addSeparator()

        # function prefixing actions
        ctx_menu.addAction(self._action_prefix)
        ctx_menu.addAction(self._action_clear_prefix)
        ctx_menu.addSeparator()

        # misc actions
        ctx_menu.addAction(self._action_refresh_metadata)

        # return the completed context menu
        return ctx_menu

    def _process_ctx_menu_action(self, action):
        """
        Process the given (user selected) context menu action.
        """

        # a right click menu action was not clicked. nothing else to do
        if not action:
            return

        # get the list rows currently selected in the coverage table
        selected_rows = self._table.selectionModel().selectedRows()
        if len(selected_rows) == 0:
            return

        #
        # extract the function addresses for the list of selected rows
        # as they will probably come in handy later.
        #

        function_addresses = []
        for index in selected_rows:
            address = self._model.row2func[index.row()]
            function_addresses.append(address)

        # handle the 'Prefix functions' action
        if action == self._action_prefix:
            gui_prefix_functions(function_addresses)

        # handle the 'Clear prefix' action
        elif action == self._action_clear_prefix:
            clear_prefixes(function_addresses)

        # handle the 'Refresh metadata' action
        elif action == self._action_refresh_metadata:

            idaapi.show_wait_box("Building database metadata...")
            self._director.refresh()

            # ensure the table's model gets refreshed
            idaapi.replace_wait_box("Refreshing Coverage Overview...")
            self.refresh()

            # all done
            idaapi.hide_wait_box()

        # handle the 'Rename' action (only applies to a single function)
        if action == self._action_rename and len(selected_rows) == 1:
            gui_rename_function(function_addresses[0])

        # handle the 'Copy name and address' or 'Copy names and addresses' action
        elif action in [self._action_copy_name_and_address, self._action_copy_names_and_addresses]:
            function_name_and_address = ""
            for idx, val in enumerate(selected_rows):
                name_index = self._model.index(val.row(), FUNC_NAME)
                function_name_and_address += "0x%X" % function_addresses[idx]
                function_name_and_address += " "
                function_name_and_address += self._model.data(name_index, QtCore.Qt.DisplayRole)
                function_name_and_address += "\n"
            copy_to_clipboard(function_name_and_address)

        # handle the 'Copy name' or 'Copy names' action
        elif action in [self._action_copy_name, self._action_copy_names]:
            function_name = ""
            for val in selected_rows:
                name_index = self._model.index(val.row(), FUNC_NAME)
                function_name += self._model.data(name_index, QtCore.Qt.DisplayRole)
                function_name += "\n"
            copy_to_clipboard(function_name)

        # handle the 'Copy address' or 'Copy addresses' action
        elif action in [self._action_copy_address, self._action_copy_addresses]:
            address_string = ""
            for val in function_addresses:
                address_string += "0x%X" % val
                address_string += "\n"
            copy_to_clipboard(address_string)

    #--------------------------------------------------------------------------
    # TODO
    #--------------------------------------------------------------------------

    def hide_zero_coverage(self, hide):
        """
        Hide functions with zero percent coverage from the table.
        """
        self._model.filter_zero_coverage(hide)

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    def refresh(self):
        """
        Public refresh of the coverage table.
        """
        self._model.refresh()

#------------------------------------------------------------------------------
# Coverage Table Model
#------------------------------------------------------------------------------

class CoverageTableModel(QtCore.QAbstractTableModel):
    """
    A Qt model interface to format coverage data for the CoverageTable.
    """

    def __init__(self, director, parent=None):
        super(CoverageTableModel, self).__init__(parent)
        self._blank_coverage = FunctionCoverage(idaapi.BADADDR)

        # local reference to the director
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
        self._director.metadata_modified(self._data_changed)

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
            try:
                function_address  = self.row2func[index.row()]
                function_metadata = self._director.metadata.functions[function_address]

            #
            # if we hit a KeyError, it is probably because the database metadata
            # is being refreshed and the model (this object) has yet to be
            # updated.
            #
            # this should only ever happen as a result of the user using the
            # right click 'Refresh metadata' action. And even then, only when
            # a function they undefined in the IDB is visible in the coverage
            # overview table view.
            #
            # In theory, the table should get refreshed *after* the metadata
            # refresh completes. So for now, we simply return return the filler
            # string '?'
            #

            except KeyError:
                return "?"

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

        # sum the # of instructions in all the visible functions
        instruction_count = sum(
            meta.instruction_count for meta in self._visible_metadata.itervalues()
        )

        # sum the # of instructions executed in all the visible functions
        instructions_executed = sum(
            cov.instructions_executed for cov in self._visible_coverage.itervalues()
        )

        # compute coverage percentage of the visible functions
        return (float(instructions_executed) / (instruction_count or 1))*100

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

    @idafast
    def _data_changed(self):
        """
        Notify attached views that simple model data has been updated/modified.
        """
        self.dataChanged.emit(QtCore.QModelIndex(), QtCore.QModelIndex())

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
