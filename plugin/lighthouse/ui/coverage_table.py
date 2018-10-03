import os
import time
import string
import logging
from operator import itemgetter, attrgetter

from lighthouse.util import lmsg
from lighthouse.util.qt import *
from lighthouse.util.misc import mainthread
from lighthouse.util.disassembler import disassembler
from lighthouse.coverage import FunctionCoverage, BADADDR

logger = logging.getLogger("Lighthouse.UI.Table")

#------------------------------------------------------------------------------
# CoverageTableView
#------------------------------------------------------------------------------

class CoverageTableView(QtWidgets.QTableView):
    """
    The Coverage Table View (UI)
    """

    def __init__(self, controller, model, parent=None):
        super(CoverageTableView, self).__init__(parent)
        self.setObjectName(self.__class__.__name__)

        # underlying table controller object (MVC)
        self._controller = controller

        # underlying data model for the coverage table
        self._model = model
        self.setModel(self._model)

        # configure the widget for use
        self._ui_init()

    #--------------------------------------------------------------------------
    # QTableView Overloads
    #--------------------------------------------------------------------------

    def keyPressEvent(self, event):
        """
        Overload QTableView key press events.
        """

        # remap h/j/k/l to arrow keys (VIM bindings)
        if event.key() == QtCore.Qt.Key_J:
            event = remap_key_event(event, QtCore.Qt.Key_Down)
        elif event.key() == QtCore.Qt.Key_K:
            event = remap_key_event(event, QtCore.Qt.Key_Up)
        elif event.key() == QtCore.Qt.Key_H:
            event = remap_key_event(event, QtCore.Qt.Key_Left)
        elif event.key() == QtCore.Qt.Key_L:
            event = remap_key_event(event, QtCore.Qt.Key_Right)

        # handle the keypress as normal
        super(CoverageTableView, self).keyPressEvent(event)

        #
        # after handling the keypress, immediately repaint the table. we use
        # this to try to cut down on flicker / row skipping while scrolling
        # using the keypad
        #

        self.repaint()
        flush_qt_events()

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """
        self._ui_init_table()
        self._ui_init_table_ctx_menu_actions()
        self._ui_init_header_ctx_menu_actions()
        self._ui_init_signals()

    def _ui_init_table(self):
        """
        Initialize the coverage table.
        """
        palette = self._model._director._palette
        self.setFocusPolicy(QtCore.Qt.StrongFocus)

        # widget style
        self.setStyleSheet(
            "QTableView {"
            "  gridline-color: black;"
            "  background-color: %s;" % palette.overview_bg.name() +
            #"  color: %s;" % palette.combobox_fg.name() +
            "  outline: none; "
            "} " +
            "QTableView::item:selected {"
            "  color: white; "
            "  background-color: %s;" % palette.selection.name() +
            "}"
        )

        # these properties will allow the user shrink the table to any size
        self.setMinimumHeight(0)
        self.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Ignored
        )

        #
        # Column Width
        #

        # get the font used by the table headers
        title_font = self._model.headerData(0, QtCore.Qt.Horizontal, QtCore.Qt.FontRole)
        title_fm = QtGui.QFontMetricsF(title_font)

        # get the font used by the table cell entries
        entry_font = self._model.data(0, QtCore.Qt.FontRole)
        entry_fm = QtGui.QFontMetricsF(entry_font)

        # set the initial column widths based on their title or contents
        for i in xrange(self._model.columnCount()):

            # determine the pixel width of the column header text
            title_text = self._model.headerData(i, QtCore.Qt.Horizontal)
            title_rect = title_fm.boundingRect(title_text)

            # determine the pixel width of sample column entry text
            entry_text = self._model.SAMPLE_CONTENTS[i]
            entry_rect = entry_fm.boundingRect(entry_text)

            # select the lager of the two potential column widths
            column_width = max(title_rect.width(), entry_rect.width())

            # pad the final column width to make the table less dense
            column_width = int(column_width * 1.2)

            # save the final column width
            self.setColumnWidth(i, column_width)

        #
        # Misc
        #

        # clicking the table will select the entire row, not a single cell
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # more code-friendly, readable aliases
        vh = self.verticalHeader()
        hh = self.horizontalHeader()

        # hide the *vertical* (row) headers because we don't use them
        vh.hide()

        # stretch last table column (which is blank) to fill remaining space
        hh.setStretchLastSection(True)

        # disable bolding of table column headers when table is selected
        hh.setHighlightSections(False)

        # allow sorting of the table by clicking table headers, and set the
        # default table state to be sorted by function address
        self.setSortingEnabled(True)
        hh.setSortIndicator(
            CoverageTableModel.FUNC_ADDR,
            QtCore.Qt.AscendingOrder
        )

        #
        # Row Height
        #

        # force the table row heights to be fixed height
        if USING_PYQT5:
            vh.setSectionResizeMode(QtWidgets.QHeaderView.Fixed)
        else:
            vh.setResizeMode(QtWidgets.QHeaderView.Fixed)

        # specify the fixed pixel height for the table headers
        spacing = title_fm.height() - title_fm.xHeight()
        tweak = 26*get_dpi_scale() - spacing
        hh.setFixedHeight(entry_fm.height()+tweak)

        # specify the fixed pixel height for the table rows
        # NOTE: don't ask too many questions about this voodoo math :D
        spacing = entry_fm.height() - entry_fm.xHeight()
        tweak = (17*get_dpi_scale() - spacing)/get_dpi_scale()
        vh.setDefaultSectionSize(entry_fm.height()+tweak)

    def _ui_init_table_ctx_menu_actions(self):
        """
        Initialize the right click context menu actions for the table view.
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

    def _ui_init_header_ctx_menu_actions(self):
        """
        Initialize the right click context menu actions for the table header.
        """
        self._action_alignment = QtWidgets.QAction("Center Aligned", None)
        self._action_alignment.setCheckable(True)
        self._action_alignment.setChecked(True)

    def _ui_init_signals(self):
        """
        Connect UI signals.
        """

        # jump to disassembly on table row double click
        self.doubleClicked.connect(self._ui_entry_double_click)

        # right click popup menu (table)
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._ui_table_ctx_menu_handler)

        # right click popup menu (table header)
        hh = self.horizontalHeader()
        hh.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        hh.customContextMenuRequested.connect(self._ui_header_ctx_menu_handler)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_entry_double_click(self, index):
        """
        Handle double click event on the coverage table.

        A double click on the coverage table view will jump the user to
        the corresponding function in the IDA disassembly view.
        """
        self._controller.navigate_to_function(index.row())

    def _ui_table_ctx_menu_handler(self, position):
        """
        Handle right click context menu event on the coverage table.
        """

        # create a right click menu based on the state and context
        ctx_menu = self._populate_table_ctx_menu()
        if not ctx_menu:
            return

        # show the popup menu to the user, and wait for their selection
        action = ctx_menu.exec_(self.viewport().mapToGlobal(position))

        # process the user action
        self._process_table_ctx_menu_action(action)

    def _ui_header_ctx_menu_handler(self, position):
        """
        Handle right click context menu event on the coverage table header.
        """
        hh = self.horizontalHeader()

        # get the table column where the right-click occurred
        column = hh.logicalIndexAt(position)

        # create a right click menu based on the state and context
        ctx_menu = self._populate_header_ctx_menu()
        if not ctx_menu:
            return

        # show the popup menu to the user, and wait for their selection
        action = ctx_menu.exec_(hh.viewport().mapToGlobal(position))

        # process the user action
        self._process_header_ctx_menu_action(action, column)

    #--------------------------------------------------------------------------
    # Context Menu (Table Rows)
    #--------------------------------------------------------------------------

    def _populate_table_ctx_menu(self):
        """
        Populate a context menu for the table view based on selection.

        Returns a populated QMenu, or None.
        """

        # get the list rows currently selected in the coverage table
        selected_rows = self.selectionModel().selectedRows()
        if len(selected_rows) == 0:
            return None

        # the context menu we will dynamically populate
        ctx_menu = QtWidgets.QMenu()

        #
        # if there is only one table row selected (a function entry), then
        # show the menu actions available for a single function such as
        # copy function name, address, or renaming the function.
        #

        if len(selected_rows) == 1:
            ctx_menu.addAction(self._action_rename)
            ctx_menu.addSeparator()
            ctx_menu.addAction(self._action_copy_name)
            ctx_menu.addAction(self._action_copy_address)
            ctx_menu.addAction(self._action_copy_name_and_address)
            ctx_menu.addSeparator()

        #
        # if multiple functions are selected then show actions available
        # for multiple functions.
        #

        else:
            ctx_menu.addAction(self._action_copy_names)
            ctx_menu.addAction(self._action_copy_addresses)
            ctx_menu.addAction(self._action_copy_names_and_addresses)
            ctx_menu.addSeparator()

        # function prefixing actions
        ctx_menu.addAction(self._action_prefix)
        ctx_menu.addAction(self._action_clear_prefix)

        # return the completed context menu
        return ctx_menu

    def _process_table_ctx_menu_action(self, action):
        """
        Process the given (user selected) table view context menu action.
        """

        # a right click menu action was not clicked. nothing else to do
        if not action:
            return

        # get the list rows currently selected in the coverage table
        row_indexes = self.selectionModel().selectedRows()
        rows = [index.row() for index in row_indexes]
        if len(rows) == 0:
            return

        # handle the 'Rename' action (only applies to a single function)
        if action == self._action_rename and len(rows) == 1:
            self._controller.rename_table_function(rows[0])

        # handle the 'Copy name' or 'Copy names' action
        elif action in [self._action_copy_name, self._action_copy_names]:
            self._controller.copy_name(rows)

        # handle the 'Copy address' or 'Copy addresses' action
        elif action in [self._action_copy_address, self._action_copy_addresses]:
            self._controller.copy_address(rows)

        # handle the 'Copy name and address' or 'Copy names and addresses' action
        elif action in [self._action_copy_name_and_address, self._action_copy_names_and_addresses]:
            self._controller.copy_name_and_address(rows)

        # handle the 'Prefix functions' action
        elif action == self._action_prefix:
            self._controller.prefix_table_functions(rows)

        # handle the 'Clear prefix' action
        elif action == self._action_clear_prefix:
            self._controller.clear_function_prefixes(rows)

    #--------------------------------------------------------------------------
    # Context Menu (Table Header)
    #--------------------------------------------------------------------------

    def _populate_header_ctx_menu(self):
        """
        Populate a context menu for the table header.

        Return a populated QMenu, or None.
        """
        ctx_menu = QtWidgets.QMenu()
        ctx_menu.addAction(self._action_alignment)
        return ctx_menu

    def _process_header_ctx_menu_action(self, action, column):
        """
        Process the given (user selected) table header context menu action.
        """

        # a right click menu action was not clicked. nothing else to do
        if not action:
            return

        # handle the 'Center Aligned' toggle action
        if action == self._action_alignment:
            self._controller.toggle_column_alignment(column)

#------------------------------------------------------------------------------
# CoverageTableController
#------------------------------------------------------------------------------

class CoverageTableController(object):
    """
    The Coverage Table Controller (Logic)
    """

    def __init__(self, model):
        self._model = model
        self._last_directory = None

    #---------------------------------------------------------------------------
    # Renaming
    #---------------------------------------------------------------------------

    @mainthread
    def rename_table_function(self, row):
        """
        Interactive rename of a database function via the coverage table.
        """

        # retrieve details about the function targeted for rename
        function_address = self._model.row2func[row]
        original_name = disassembler.get_function_raw_name_at(function_address)

        # prompt the user for a new function name
        ok, new_name = prompt_string(
            "Please enter function name",
            "Rename Function",
            original_name
           )

        #
        # if the user clicked cancel, or the name they entered
        # is identical to the original, there's nothing to do
        #

        if not (ok or new_name != original_name):
            return

        # rename the function
        disassembler.set_function_name_at(function_address, new_name)

    @mainthread
    def prefix_table_functions(self, rows):
        """
        Interactive prefixing of database functions via the coverage table.
        """

        # prompt the user for a new function name
        ok, prefix = prompt_string(
            "Please enter a function prefix",
            "Prefix Function(s)",
            "MyPrefix"
           )

        # bail if the user clicked cancel or failed to enter a prefix
        if not (ok and prefix):
            return

        # apply the user prefix to the functions depicted in the given rows
        function_addresses = self._get_function_addresses(rows)
        disassembler.prefix_functions(function_addresses, prefix)

    @mainthread
    def clear_function_prefixes(self, rows):
        """
        Clear prefixes of database functions via the coverage table.
        """
        function_addresses = self._get_function_addresses(rows)
        disassembler.clear_prefixes(function_addresses)

    #---------------------------------------------------------------------------
    # Copy-to-Clipboard
    #---------------------------------------------------------------------------

    @mainthread
    def copy_name(self, rows):
        """
        Copy function names for the given table rows to clipboard.
        """
        model = self._model
        function_names = ""
        for row_number in rows:
            name_index = model.index(row_number, model.FUNC_NAME)
            function_names += model.data(name_index)
            function_names += "\n"
        copy_to_clipboard(function_names.rstrip())
        return function_names

    @mainthread
    def copy_address(self, rows):
        """
        Copy function addresses for the given table rows to clipboard.
        """
        model = self._model
        address_string = ""
        for row_number in rows:
            addr_index = model.index(row_number, model.FUNC_ADDR)
            address_string += model.data(addr_index)
            address_string += "\n"
        copy_to_clipboard(address_string.rstrip())
        return address_string

    @mainthread
    def copy_name_and_address(self, rows):
        """
        Copy function name & addresses for the given table rows to clipboard.
        """
        model = self._model
        function_name_and_address = ""
        for row_number in rows:
            name_index = model.index(row_number, model.FUNC_NAME)
            addr_index = model.index(row_number, model.FUNC_ADDR)
            function_name_and_address += model.data(addr_index)
            function_name_and_address += " "
            function_name_and_address += model.data(name_index)
            function_name_and_address += "\n"
        copy_to_clipboard(function_name_and_address.rstrip())
        return function_name_and_address

    #---------------------------------------------------------------------------
    # Misc
    #---------------------------------------------------------------------------

    def navigate_to_function(self, row):
        """
        Navigate to the function depicted by the given row.
        """
        disassembler.navigate(self._model.row2func[row])

    def toggle_column_alignment(self, column):
        """
        Toggle the text alignment of given column.
        """
        index = self._model.index(0, column)
        alignment = self._model.data(index, QtCore.Qt.TextAlignmentRole)

        # toggle the column alignment between center (default) and left
        if alignment == QtCore.Qt.AlignCenter:
            new_alignment = QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter
        else:
            new_alignment = QtCore.Qt.AlignCenter

        # send the new alignment to the model
        self._model.set_column_alignment(column, new_alignment)

    def refresh_metadata(self):
        """
        Hard refresh of the director and table metadata layers.
        """
        disassembler.show_wait_box("Building database metadata...")
        self._model._director.refresh()

        # ensure the table's model gets refreshed
        disassembler.replace_wait_box("Refreshing Coverage Overview...")
        self._model.refresh()

        # all done
        disassembler.hide_wait_box()

    def export_to_html(self):
        """
        Export the coverage table to an HTML report.
        """
        if not self._last_directory:
            self._last_directory = disassembler.get_database_directory()

        # build filename for the coverage report based off the coverage name
        name, _ = os.path.splitext(self._model._director.coverage_name)
        filename = name + ".html"
        suggested_filepath = os.path.join(self._last_directory, filename)

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtWidgets.QFileDialog()
        file_dialog.setFileMode(QtWidgets.QFileDialog.AnyFile)

        # we construct kwargs here for cleaner PySide/PyQt5 compatibility
        kwargs = \
        {
            "filter": "HTML Files (*.html)",
            "caption": "Save HTML Report",
            "directory" if USING_PYQT5 else "dir": suggested_filepath
        }

        # prompt the user with the file dialog, and await their chosen filename(s)
        filename, _ = file_dialog.getSaveFileName(**kwargs)
        if not filename:
            return

        # remember the last directory we were in (parsed from the saved file)
        self._last_directory = os.path.dirname(filename) + os.sep

        # write the generated HTML report to disk
        with open(filename, "wb") as fd:
            fd.write(self._model.to_html())

        lmsg("Saved HTML report to %s" % filename)

    #---------------------------------------------------------------------------
    # Internal
    #---------------------------------------------------------------------------

    def _get_function_addresses(self, rows):
        """
        Return the function addresses for the given rows.
        """
        function_addresses = []
        for row_number in rows:
            address = self._model.row2func[row_number]
            function_addresses.append(address)
        return function_addresses

#------------------------------------------------------------------------------
# CoverageTableModel
#------------------------------------------------------------------------------

class CoverageTableModel(QtCore.QAbstractTableModel):
    """
    A Qt model interface to format coverage data for Qt views.
    """

    # named constants for coverage table column indexes
    COV_PERCENT  = 0
    FUNC_NAME    = 1
    FUNC_ADDR    = 2
    BLOCKS_HIT   = 3
    INST_HIT     = 4
    FUNC_SIZE    = 5
    COMPLEXITY   = 6
    FINAL_COLUMN = 7

    METADATA_ATTRIBUTES = [FUNC_NAME, FUNC_ADDR, FUNC_SIZE, COMPLEXITY]
    COVERAGE_ATTRIBUTES = [COV_PERCENT, BLOCKS_HIT, INST_HIT]

    # column index -> object attribute mapping
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
    COLUMN_HEADERS = \
    {
        COV_PERCENT:  "Coverage %",
        FUNC_NAME:    "Function Name",
        FUNC_ADDR:    "Address",
        BLOCKS_HIT:   "Blocks Hit",
        INST_HIT:     "Instructions Hit",
        FUNC_SIZE:    "Function Size",
        COMPLEXITY:   "Complexity",
        FINAL_COLUMN: ""
    }

    # sample column
    SAMPLE_CONTENTS = \
    [
        " 100.00% ",
        " sub_140001B20 ",
        " 0x140001b20 ",
        " 100 / 100 ",
        " 1000 / 1000 ",
        " 10000000 ",
        " 1000000 ",
        ""
    ]

    def __init__(self, director, parent=None):
        super(CoverageTableModel, self).__init__(parent)
        self._director = director

        # convenience mapping from row_number --> function_address
        self.row2func = {}
        self._row_count = 0

        # an internal mapping of the data / coverage to make visible
        self._no_coverage = []
        self._visible_metadata = {}
        self._visible_coverage = {}

        # a fallback coverage object for functions with no coverage
        self._blank_coverage = FunctionCoverage(BADADDR)
        self._blank_coverage.coverage_color = director._palette.coverage_none

        # set the default column text alignment for each column (centered)
        self._default_alignment = QtCore.Qt.AlignCenter
        self._column_alignment = [
            self._default_alignment for x in self.COLUMN_HEADERS
        ]

        # initialize a monospace font to use for table row / cell text
        self._entry_font = MonospaceFont()
        self._entry_font.setStyleStrategy(QtGui.QFont.ForceIntegerMetrics)
        self._entry_font.setPointSizeF(normalize_to_dpi(9))

        # use the default / system font for the column titles
        self._title_font = QtGui.QFont()
        self._title_font.setPointSizeF(normalize_to_dpi(9))

        #----------------------------------------------------------------------
        # Sorting
        #----------------------------------------------------------------------

        # attributes to track the model's last known (column) sort state
        self._last_sort = self.FUNC_ADDR
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
    # QAbstractTableModel Overloads
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
        return len(self.COLUMN_HEADERS)

    def headerData(self, column, orientation, role=QtCore.Qt.DisplayRole):
        """
        Define the properties of the table rows & columns.
        """

        if orientation == QtCore.Qt.Horizontal:

            # the title of the header columns has been requested
            if role == QtCore.Qt.DisplayRole:
                return self.COLUMN_HEADERS[column]

            # the text alignment of the header has been requested
            elif role == QtCore.Qt.TextAlignmentRole:

                # center align all columns
                return self._column_alignment[column]

            # font format request
            elif role == QtCore.Qt.FontRole:
                return self._title_font

        # unhandeled header request
        return None

    def data(self, index, role=QtCore.Qt.DisplayRole):
        """
        Define how Qt should access the underlying model data.
        """

        # a request has been made for what text to show in a table cell
        if role == QtCore.Qt.DisplayRole:

            # alias the requested column number once, for readability & perf
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
            if column == self.COV_PERCENT:
                return "%5.2f" % (function_coverage.instruction_percent*100)

            # Function Name
            elif column == self.FUNC_NAME:
                return function_metadata.name

            # Function Address
            elif column == self.FUNC_ADDR:
                return "0x%X" % function_metadata.address

            # Basic Blocks
            elif column == self.BLOCKS_HIT:
                return "%3u / %-3u" % (function_coverage.nodes_executed,
                                       function_metadata.node_count)

            # Instructions Hit
            elif column == self.INST_HIT:
                return "%4u / %-4u" % (function_coverage.instructions_executed,
                                       function_metadata.instruction_count)

            # Function Size
            elif column == self.FUNC_SIZE:
                return "%u" % function_metadata.size

            # Cyclomatic Complexity
            elif column == self.COMPLEXITY:
                return "%u" % function_metadata.cyclomatic_complexity

        # cell background color request
        elif role == QtCore.Qt.BackgroundRole:
            function_address  = self.row2func[index.row()]
            function_coverage = self._director.coverage.functions.get(
                function_address,
                self._blank_coverage
            )
            return function_coverage.coverage_color

        # cell text color request
        elif role == QtCore.Qt.ForegroundRole:
            return QtGui.QColor(QtCore.Qt.white)

        # cell font style format request
        elif role == QtCore.Qt.FontRole:
            return self._entry_font

        # cell text alignment request
        elif role == QtCore.Qt.TextAlignmentRole:
            return self._column_alignment[index.column()]

        # unhandeled request, nothing to do
        return None

    #--------------------------------------------------------------------------
    # Sorting
    #--------------------------------------------------------------------------

    def sort(self, column, sort_order):
        """
        Sort the coverage table rows by the selected column, and direction.
        """

        #
        # look up the name of field in the FunctionCoverage class object
        # that we would like to sort by based on the selected column
        #

        try:
            sort_field = self.COLUMN_TO_FIELD[column]

        # column has not been enlightened to sorting
        except KeyError as e:
            logger.warning("TODO/FUTURE: implement column %u sorting?" % column)
            self.layoutChanged.emit()
            return

        #
        # NOTE: attrgetter appears to profile ~8-12% faster than lambdas
        #   accessing the member on the member, hence the strange paradigm
        #

        # sort the table entries by a function metadata attribute
        if column in self.METADATA_ATTRIBUTES:
            sorted_functions = sorted(
                self._visible_metadata.itervalues(),
                key=attrgetter(sort_field),
                reverse=sort_order
            )

        # sort the table entries by a function coverage attribute
        elif column in self.COVERAGE_ATTRIBUTES:
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

    def set_column_alignment(self, column, alignment):
        """
        Set the text alignment of the given column.
        """
        self._column_alignment[column] = alignment

        # redraw the column header & row contents with the new alignment
        self._alignment_changed(column)

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
    # HTML Export
    #--------------------------------------------------------------------------

    def to_html(self):
        """
        Generate an HTML representation of the coverage table.
        """

        # table summary
        summary_html, summary_css = self._generate_html_summary()

        # coverage table
        table_html, table_css = self._generate_html_table()

        # page body
        body_elements = [summary_html, table_html]
        body_html = "<body>%s</body>" % '\n'.join(body_elements)
        body_css = \
        """
        body {
            font-family: Arial, Helvetica, sans-serif;

            color: white;
            background-color: #363636;
        }
        """

        # HTML <head> tag
        css_elements = [body_css, summary_css, table_css]
        head_contents = "<style>%s</style>" % '\n'.join(css_elements)
        head_html = "<head>%s</head>" % head_contents

        # generate the final HTML page
        page_elements = [head_html, body_html]
        page_html = "<html>%s</html>" % '\n'.join(page_elements)

        # return the generated HTML report
        return page_html

    def _generate_html_summary(self):
        """
        Generate the HTML table summary.
        """
        metadata = self._director.metadata
        coverage = self._director.coverage

        # page title
        title_html = "<h1>Lighthouse Coverage Report</h1>"

        # summary details
        detail = lambda x,y: '<li><span class="detail">%s:</span> %s</li>' % (x,y)
        database_percent = coverage.instruction_percent*100
        table_percent = self.get_modeled_coverage_percent()
        details = \
        [
            detail("Target Binary", metadata.filename),
            detail("Coverage Name", coverage.name),
            detail("Coverage File", coverage.filepath),
            detail("Database Coverage", "%1.2f%%" % database_percent),
            detail("Table Coverage", "%1.2f%%" % table_percent),
            detail("Timestamp", time.ctime()),
        ]
        list_html = "<ul>%s</ul>" % '\n'.join(details)
        list_css = \
        """
        .detail { font-weight: bold; color: white; }
        li { color: #c0c0c0; }
        """

        # title + summary
        summary_html = title_html + list_html
        summary_css = list_css
        return (summary_html, summary_css)

    def _generate_html_table(self):
        """
        Generate the HTML coverage table.
        """
        palette = self._director._palette
        table_rows = []

        # generate the table's column title row
        header_cells = []
        for i in xrange(self.columnCount()-1):
            header_cells.append(
                "<th>%s</th>" % self.headerData(i, QtCore.Qt.Horizontal)
            )
        table_rows.append(("#505050", header_cells))

        # generate the table's coverage rows
        for row in xrange(self.rowCount()):
            row_cells = []
            for column in xrange(self.columnCount()-1):
                index = self.index(row, column)
                row_cells.append("<td>%s</td>" % self.data(index))
            row_color = self.data(index, QtCore.Qt.BackgroundRole).name()
            table_rows.append((row_color, row_cells))

        # wrap each row of cells, into an HTML table row
        html_rows = []
        for row_color, row_cells in table_rows:
            cell_html = ''.join(row_cells)
            html_rows.append("<tr style='background-color: %s'>%s</tr>" % (row_color, cell_html))

        # generate the final HTML table
        table_html = "<table>%s</table>" % '\n'.join(html_rows)
        table_css = \
        """
        table {{
            text-align: center;
            white-space: pre;
            border-collapse: collapse;

            background-color: {table_bg};
            color: {table_fg};
        }}

        table, th, td {{
            border: 1px solid black;
        }}

        table tr td:nth-child(2) {{
            text-align: left;
        }}

        td {{
            font-family: "Courier New", Courier, monospace;
            font-size: 11pt;
            padding: 0.5ex 1ex 0.5ex 1ex;
        }}

        th {{
            padding: 1ex 1em 1ex 1em;
        }}
        """.format(
            table_bg=palette.overview_bg.name(),
            table_fg="white"
        )

        return (table_html, table_css)

    #--------------------------------------------------------------------------
    # Filters
    #--------------------------------------------------------------------------

    def filter_zero_coverage(self, hide):
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

    @disassembler.execute_ui
    def _internal_refresh(self):
        """
        Internal refresh of the coverage model.
        """
        self._refresh_data()

        # sort the data set according to the last selected sorted column
        self.sort(self._last_sort, self._last_sort_order)

    @mainthread
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
        # that means we want to 'normalize' all the function names by making
        # them lowercase before searching for our needle (search str)
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

    #--------------------------------------------------------------------------
    # Qt Notifications
    #--------------------------------------------------------------------------

    @disassembler.execute_ui
    def _data_changed(self):
        """
        Notify attached views that simple model data has been updated/modified.
        """
        self.dataChanged.emit(QtCore.QModelIndex(), QtCore.QModelIndex())

    @disassembler.execute_ui
    def _alignment_changed(self, column):
        """
        Notify attached views that the column alignment has been changed.
        """
        self.dataChanged.emit(QtCore.QModelIndex(), QtCore.QModelIndex())
        self.headerDataChanged.emit(QtCore.Qt.Horizontal, column, column)
