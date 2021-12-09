import os
import time
import string
import logging
from textwrap import dedent
from operator import itemgetter, attrgetter

from lighthouse.util import lmsg
from lighthouse.util.qt import *
from lighthouse.util.python import *
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
        self.refresh_theme()

    @disassembler.execute_ui
    def refresh_theme(self):
        """
        Refresh UI facing elements to reflect the current theme.
        """
        palette = self._model.lctx.palette
        self.setStyleSheet(
            "QTableView {"
            "  gridline-color: %s;" % palette.table_grid.name() +
            "  background-color: %s;" % palette.table_background.name() +
            "  color: %s;" % palette.table_text.name() +
            "  outline: none; "
            "} " +
            "QHeaderView::section { "
            "  padding: 1ex;"  \
            "  margin: 0;"  \
            "} " +
            "QTableView::item:selected {"
            "  color: white; "
            "  background-color: %s;" % palette.table_selection.name() +
            "}"
        )

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
        self.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)

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

        # get the font used by the table cell entries
        entry_font = self._model.data(0, QtCore.Qt.FontRole)
        entry_fm = QtGui.QFontMetricsF(entry_font)

        # set the initial column widths based on their title or contents
        for i in xrange(self._model.columnCount()):

            # determine the pixel width of the column header text
            title_rect = self._model.headerData(i, QtCore.Qt.Horizontal, QtCore.Qt.SizeHintRole)

            # determine the pixel width of sample column entry text
            entry_text = self._model.SAMPLE_CONTENTS[i]
            entry_rect = entry_fm.boundingRect(entry_text)

            # select the larger of the two potential column widths
            column_width = int(max(title_rect.width(), entry_rect.width()*1.2))

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
        #hh.setStretchLastSection(True)
        #hh.setCascadingSectionResizes(True)
        hh.setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)

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
        vh.setSectionResizeMode(QtWidgets.QHeaderView.Fixed)

        # specify the fixed pixel height for the table rows
        # NOTE: don't ask too many questions about this voodoo math :D
        spacing = entry_fm.height() - entry_fm.xHeight()
        tweak = (17*get_dpi_scale() - spacing)/get_dpi_scale()
        vh.setDefaultSectionSize(int(entry_fm.height()+tweak))

    def _ui_init_table_ctx_menu_actions(self):
        """
        Initialize the right click context menu actions for the table view.
        """

        # misc actions
        self._action_dump_orphan = QtWidgets.QAction("Dump orphan addresses", None)
        self._action_dump_internal = QtWidgets.QAction("Dump internal addresses (Debug)", None)

        # function actions
        self._action_rename = QtWidgets.QAction("Rename", None)
        self._action_copy_name = QtWidgets.QAction("Copy name", None)
        self._action_copy_address = QtWidgets.QAction("Copy address", None)
        self._action_copy_name_and_address = QtWidgets.QAction("Copy name and address", None)
        self._action_export_graphml = QtWidgets.QAction("Export coverage graph as GraphML", None)

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
        if USING_PYSIDE6:
            exec_func = getattr(ctx_menu, "exec")
        else:
            exec_func = getattr(ctx_menu, "exec_")

        action = exec_func(self.viewport().mapToGlobal(position))

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
        if USING_PYSIDE6:
            exec_func = getattr(ctx_menu, "exec")
        else:
            exec_func = getattr(ctx_menu, "exec_")
        action = exec_func(hh.viewport().mapToGlobal(position))

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
        selected_row_indexes = self.selectionModel().selectedRows()
        if len(selected_row_indexes) == 0:
            return None

        # the context menu we will dynamically populate
        ctx_menu = QtWidgets.QMenu()

        #
        # if there is only one table row selected (a function entry), then
        # show the menu actions available for a single function such as
        # copy function name, address, or renaming the function.
        #

        if len(selected_row_indexes) == 1:

            row = selected_row_indexes[0].row()
            function_address = self._model.row2func[row]

            # special handling for right click of orphan coverage row
            if function_address == BADADDR:
                ctx_menu.addAction(self._action_dump_orphan)
                ctx_menu.addAction(self._action_dump_internal)
                return ctx_menu

            # normal right click of a function row
            else:
                ctx_menu.addAction(self._action_rename)
                ctx_menu.addSeparator()
                ctx_menu.addAction(self._action_copy_name)
                ctx_menu.addAction(self._action_copy_address)
                ctx_menu.addAction(self._action_copy_name_and_address)
                ctx_menu.addSeparator()
                ctx_menu.addAction(self._action_export_graphml)
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

        # handle the 'Export to GraphML' action (only applies to a single function)
        elif action == self._action_export_graphml and len(rows) == 1:
            self._controller.export_to_graphml(rows[0])

        # handle the 'Prefix functions' action
        elif action == self._action_prefix:
            self._controller.prefix_table_functions(rows)

        # handle the 'Clear prefix' action
        elif action == self._action_clear_prefix:
            self._controller.clear_function_prefixes(rows)

        # handle the 'Dump orphan addresses' action
        elif action == self._action_dump_orphan:
            self._controller.dump_orphan()

        # handle the 'Dump internal addresses' action
        elif action == self._action_dump_internal:
            self._controller.dump_internal()

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

    def __init__(self, lctx, model):
        self.lctx = lctx
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
        if function_address == BADADDR:
            return

        original_name = disassembler[self.lctx].get_function_raw_name_at(function_address)

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
        disassembler[self.lctx].set_function_name_at(function_address, new_name)

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
        disassembler[self.lctx].prefix_functions(function_addresses, prefix)

    @mainthread
    def clear_function_prefixes(self, rows):
        """
        Clear prefixes of database functions via the coverage table.
        """
        function_addresses = self._get_function_addresses(rows)
        disassembler[self.lctx].clear_prefixes(function_addresses)

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

    #--------------------------------------------------------------------------
    # Dumping
    #--------------------------------------------------------------------------

    def dump_orphan(self):
        """
        Dump the orphan coverage data.
        """
        coverage = self.lctx.director.coverage
        lmsg("Orphan coverage addresses for %s:" % coverage.name)
        self._dump_addresses(coverage.orphan_addresses)

    def dump_internal(self):
        """
        Dump the internal coverage data.
        """
        coverage = self.lctx.director.coverage
        lmsg("Internal coverage addresses for %s:" % coverage.name)
        self._dump_addresses(coverage.unmapped_addresses)

    def _dump_addresses(self, coverage_addresses):
        """
        Dump the given list of addresses to the terminal.
        """
        coverage_addresses = sorted(coverage_addresses)
        if not coverage_addresses:
            lmsg(" * (there is no addresses to dump)")
            return

        for address in coverage_addresses:
            lmsg(" * 0x%X" % address)

    #---------------------------------------------------------------------------
    # Misc
    #---------------------------------------------------------------------------

    def navigate_to_function(self, row):
        """
        Navigate to the function depicted by the given row.
        """

        # get the clicked function address
        function_address = self._model.row2func[row]
        if function_address == BADADDR:
            return

        #
        # if there is actually coverage in the function, attempt to locate the
        # first block (or any block) with coverage and set that as our target
        #

        function_coverage = self.lctx.director.coverage.functions.get(function_address, None)
        if function_coverage:
            if function_address in function_coverage.nodes:
                target_address = function_address
            else:
                target_address = sorted(function_coverage.nodes)[0]

        #
        # if the user clicked a function with no coverage, we should just
        # navigate to the top of the function... nothing fancy
        #

        else:
            target_address = function_address

        # navigate to the target function + block
        disassembler[self.lctx].navigate_to_function(function_address, target_address)

    def toggle_column_alignment(self, column):
        """
        Toggle the text alignment of given column.
        """
        index = self._model.index(0, column)
        alignment = self._model.data(index, QtCore.Qt.TextAlignmentRole)

        # toggle the column alignment between center (default) and left
        if alignment == QtCore.Qt.AlignCenter:
            new_alignment = QtCore.Qt.AlignVCenter
        else:
            new_alignment = QtCore.Qt.AlignCenter

        # send the new alignment to the model
        self._model.set_column_alignment(column, new_alignment)

    def export_to_html(self):
        """
        Export the coverage table to an HTML report.
        """
        if not self._last_directory:
            self._last_directory = disassembler[self.lctx].get_database_directory()

        # build filename for the coverage report based off the coverage name
        name, _ = os.path.splitext(self.lctx.director.coverage_name)
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
            "directory": suggested_filepath
        }

        # prompt the user with the file dialog, and await their chosen filename(s)
        filename, _ = file_dialog.getSaveFileName(**kwargs)
        if not filename:
            return

        # remember the last directory we were in (parsed from the saved file)
        self._last_directory = os.path.dirname(filename) + os.sep

        # write the generated HTML report to disk
        with open(filename, "w") as fd:
            fd.write(self._model.to_html())

        lmsg("Saved HTML report to %s" % filename)

    def export_to_graphml(self, row):
        """
        Export the coverage representation to GraphML format, using
        selected row (function) in coverage table as a graph root.
        """
        if not self._last_directory:
            self._last_directory = disassembler[self.lctx].get_database_directory()

        # build filename for the report based on the coverage name and root function name
        name, _ = os.path.splitext(self.lctx.director.coverage_name)
        func_name = self._model.data(self._model.index(row, self._model.FUNC_NAME))
        name += "_" + func_name
        filename = name + ".graphml"
        suggested_filepath = os.path.join(self._last_directory, filename)

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtWidgets.QFileDialog()
        file_dialog.setFileMode(QtWidgets.QFileDialog.AnyFile)

        # we construct kwargs here for cleaner PySide/PyQt5 compatibility
        kwargs = \
            {
                "filter": "GraphML Files (*.graphml)",
                "caption": "Save GraphML Coverage Representation",
                "directory": suggested_filepath
            }

        # prompt the user with the file dialog, and await their chosen filename(s)
        filename, _ = file_dialog.getSaveFileName(**kwargs)
        if not filename:
            return

        # remember the last directory we were in (parsed from the saved file)
        self._last_directory = os.path.dirname(filename) + os.sep

        # write the generated GraphML representation to a disk
        with open(filename, "w") as fd:
            # get the clicked function address
            function_address = self._model.row2func[row]
            graphml_data, coverage_percentage = self._model.to_graphml(function_address)
            fd.write(graphml_data)

        lmsg("Saved GraphML coverage representation to %s" % filename)
        lmsg("Coverage of a reachable code from %s is %.2f" % (func_name, coverage_percentage * 100))

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
            if address != BADADDR:
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
        COV_PERCENT:  "Cov %",
        FUNC_NAME:    "Func Name",
        FUNC_ADDR:    "Address",
        BLOCKS_HIT:   "Blocks Hit",
        INST_HIT:     "Instr. Hit",
        FUNC_SIZE:    "Func Size",
        COMPLEXITY:   "CC",
    }

    # column header tooltips
    COLUMN_TOOLTIPS = \
    {
        COV_PERCENT:  "Coverage Percent",
        FUNC_NAME:    "Function Name",
        FUNC_ADDR:    "Function Address",
        BLOCKS_HIT:   "Number of Basic Blocks Executed",
        INST_HIT:     "Number of Instructions Executed",
        FUNC_SIZE:    "Function Size (bytes)",
        COMPLEXITY:   "Cyclomatic Complexity",
    }

    # sample column
    SAMPLE_CONTENTS = \
    [
        " 100.00 ",
        " sub_140001B20 ",
        " 0x140001b20 ",
        " 100 / 100 ",
        " 1000 / 1000 ",
        " 100000 ",
        " 1000 ",
    ]

    def __init__(self, lctx, parent=None):
        super(CoverageTableModel, self).__init__(parent)
        self.lctx = lctx
        self._director = lctx.director

        # convenience mapping from row_number --> function_address
        self.row2func = {}
        self._row_count = 0

        # an internal mapping of the data / coverage to make visible
        self._no_coverage = []
        self._visible_metadata = {}
        self._visible_coverage = {}

        # a fallback coverage object for functions with no coverage
        self._blank_coverage = FunctionCoverage(BADADDR)
        self._blank_coverage.coverage_color = lctx.palette.table_coverage_none

        # set the default column text alignment for each column (centered)
        self._default_alignment = QtCore.Qt.AlignCenter
        self._column_alignment = [
            self._default_alignment for x in self.COLUMN_HEADERS
        ]

        # make the function name column left aligned by default
        self.set_column_alignment(self.FUNC_NAME, QtCore.Qt.AlignVCenter)

        # initialize a monospace font to use for table row / cell text
        self._entry_font = MonospaceFont()
        if not USING_PYSIDE6:
            #TODO Figure out if this matters?
            self._entry_font.setStyleStrategy(QtGui.QFont.ForceIntegerMetrics)
        self._entry_font.setPointSizeF(normalize_to_dpi(10))

        # use the default / system font for the column titles
        self._title_font = QtGui.QFont()
        self._title_font.setPointSizeF(normalize_to_dpi(10))

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
        self._director.metadata.function_renamed(self._data_changed)

    def refresh_theme(self):
        """
        Refresh UI facing elements to reflect the current theme.

        Does not require @disassembler.execute_ui decorator, data_changed() has its own.
        """
        self._blank_coverage.coverage_color = self.lctx.palette.table_coverage_none
        self._data_changed()

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

            # tooltip request
            elif role == QtCore.Qt.ToolTipRole:
                return self.COLUMN_TOOLTIPS[column]

            # font format request
            elif role == QtCore.Qt.FontRole:
                return self._title_font

        if role == QtCore.Qt.SizeHintRole:
            title_fm = QtGui.QFontMetricsF(self._title_font)
            title_rect = title_fm.boundingRect(self.COLUMN_HEADERS[column])
            padded = QtCore.QSize(int(title_rect.width()*1.45), int(title_rect.height()*1.75))
            return padded

        # unhandeled header request
        return None

    def _data_function_display(self, function_address, column):
        """
        Return a string to diplay in the requested column of the given function.
        """

        # lookup the function info for the given function
        try:
            function_metadata = self.lctx.metadata.functions[function_address]

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

        # unhandeled? maybe make this an assert?
        return None

    def _data_orphan_display(self, column):
        """
        Return a string to be displayed by the table
        """
        if column == self.FUNC_NAME:
            return "Orphan Coverage"
        elif column == self.INST_HIT:
            return "%u" % len(self._director.coverage.orphan_addresses)
        return "N/A"

    def data(self, index, role=QtCore.Qt.DisplayRole):
        """
        Define how Qt should access the underlying model data.
        """

        # a request has been made for what text to show in a table cell
        if role == QtCore.Qt.DisplayRole:

            column = index.column()
            function_address = self.row2func[index.row()]

            if function_address == BADADDR:
                return self._data_orphan_display(column)
            else:
                return self._data_function_display(function_address, column)

        # cell background color request
        elif role == QtCore.Qt.BackgroundRole:
            function_address  = self.row2func[index.row()]

            # special handling for 'orphan' coverage
            if function_address == BADADDR:

                # if there was *ANY* coverage, color the 'orphan' line red
                if self._director.coverage.orphan_addresses:
                    return self.lctx.palette.table_coverage_bad

            # normal handling
            function_coverage = self._director.coverage.functions.get(
                function_address,
                self._blank_coverage
            )

            return function_coverage.coverage_color

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
            logger.error("ERROR: Sorting not implemented for column %u" % column)
            self.layoutChanged.emit()
            return

        #
        # NOTE: attrgetter appears to profile ~8-12% faster than lambdas
        #   accessing the member on the member, hence the strange paradigm
        #

        # sort the table entries by a function metadata attribute
        if column in self.METADATA_ATTRIBUTES:
            sorted_functions = sorted(
                itervalues(self._visible_metadata),
                key=attrgetter(sort_field),
                reverse=sort_order
            )

        # sort the table entries by a function coverage attribute
        elif column in self.COVERAGE_ATTRIBUTES:
            sorted_functions = sorted(
                itervalues(self._visible_coverage),
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
        self.row2func[len(self.row2func)] = BADADDR
        self.func2row = {v: k for k, v in iteritems(self.row2func)}
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
            meta.instruction_count for meta in itervalues(self._visible_metadata)
        )

        # sum the # of instructions executed in all the visible functions
        instructions_executed = sum(
            cov.instructions_executed for cov in itervalues(self._visible_coverage)
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
        palette = self.lctx.palette

        # table summary
        summary_html, summary_css = self._generate_html_summary()

        # coverage table
        table_html, table_css = self._generate_html_table()

        # page body
        body_elements = [summary_html, table_html]
        body_html = "<body>%s</body>" % '\n'.join(body_elements)
        body_css = \
        """
        body {{
            font-family: Arial, Helvetica, sans-serif;

            color: {page_fg};
            background-color: {page_bg};
        }}
        """.format(
            page_fg=palette.table_text.name(),
            page_bg=palette.html_page_background.name()
        )

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
        palette = self.lctx.palette
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
        .detail {{
            font-weight: bold;
            color: {page_fg};
        }}
        li {{
            color: {detail_fg};
        }}
        """.format(
            page_fg=palette.table_text.name(),
            detail_fg=palette.html_summary_text.name()
        )

        # title + summary
        summary_html = title_html + list_html
        summary_css = list_css
        return (summary_html, summary_css)

    def _generate_html_table(self):
        """
        Generate the HTML coverage table.
        """
        palette = self.lctx.palette
        table_rows = []

        # generate the table's column title row
        header_cells = []
        for i in xrange(self.columnCount()-1):
            header_cells.append(
                "<th>%s</th>" % self.headerData(i, QtCore.Qt.Horizontal)
            )
        table_rows.append((palette.html_table_header.name(), header_cells))

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
            table_bg=palette.table_background.name(),
            table_fg=palette.table_text.name()
        )

        return (table_html, table_css)

    #--------------------------------------------------------------------------
    # GraphML Export
    #--------------------------------------------------------------------------
    #
    # Export to GraphML representation can be used for analyzing code coverage
    # as a system of functions. Exported file is a graph of all reachable code
    # from specified by the user function.
    # Graph details:
    # - Graph is a directed graph;
    # - Nodes are functions;
    # - Edges are set from caller function to callee function;
    # - Each node contains the following information:
    #   * Function size (in bytes);
    #   * Function coverage percentage;
    #   * Cyclomatic complexity value;
    #   * Amount of memory read/write references;
    #   * Number of polygon vertices that can be used as a shape of the node.
    #
    # Notes about the number of polygon vertices that can be used as a shape
    # of the node:
    # The number of such vertices reflects the corresponding cyclomatic
    # complexity value, so cyclomatic complexity can be visualized as the
    # shape of the corresponding node - the more cyclomatic complexity is the
    # more vertices polygon has. During the export, the relation between
    # cyclomatic complexity value and number of polygon vertices is computed
    # based on overall complexity of all current graph functions in order to
    # achieve efficient distribution of polygon vertices.
    #

    def to_graphml(self, start_function_address):
        """
        Generate a GraphML representation of the active coverage, using
        start_function_address as a graph root.
        """
        metadata = self._director.metadata

        #
        # GraphML header data and node properties declaration.
        # We use textwrap.dedent() in order to delete common leading
        # whitespaces and make string lines up with the left edge of
        # the display
        #

        graphml_data = dedent("""\
        <?xml version="1.0" encoding="UTF-8"?>
        <graphml xmlns="http://graphml.graphdrawing.org/xmlns"  
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns 
                 http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">
            <key id="polygon" for="node" attr.name="Polygon" attr.type="int">
                <default>0</default>
            </key>
            <key id="label" for="node" attr.name="Label" attr.type="string"/>
            <key id="fsize" for="node" attr.name="FuncSize" attr.type="int"/>
            <key id="cov" for="node" attr.name="Coverage" attr.type="double"/>
            <key id="cc" for="node" attr.name="Complexity" attr.type="int"/>
            <key id="mem_ref" for="node" attr.name="MemReferenceCount" attr.type="int"/>
            <graph edgedefault="directed">
        """)

        start_func_metadata = metadata.functions.get(start_function_address)
        if start_func_metadata is None:
            return None

        #
        # generate GraphML edges.
        # NOTE: we generate edges and nodes separately in order to compute
        # correct number of vertices of polygons which can be used as shapes of
        # the graph nodes
        #

        graph_nodes, graphml_edges_data = self._generate_graphml_edges(start_func_metadata)
        graphml_data += graphml_edges_data
        # generate GraphML nodes
        coverage_percentage, graphml_nodes_data = self._generate_graphml_nodes(graph_nodes)
        graphml_data += graphml_nodes_data

        # enclosing GraphML tags
        graphml_data += dedent("""\
            </graph>
        </graphml>
        """)

        # return final GraphML representation and the coverage percentage
        return graphml_data, coverage_percentage

    def _generate_graphml_edges(self, start_function_metadata):
        """
        Traverse functions referenced from start function and
        generate GraphML edges data.
        """
        metadata = self._director.metadata

        # queue for breadth-first traversal of the graph
        nodes_queue = queue.Queue()
        # list to store already traversed nodes
        nodes_traversed = []
        edges_num = 0

        graphml_edges_data = ""

        # nested function for edges wrapping.
        def edge_wrapper(num, source, target):
            # escape XML special characters in source and target
            escape_mapping = {"<": " &lt; ", ">": " &gt; ", "&": " &amp; "}
            escape_trans_table = source.maketrans(escape_mapping)
            source = source.translate(escape_trans_table)
            escape_trans_table = target.maketrans(escape_mapping)
            target = target.translate(escape_trans_table)
            # we need two tabs indent for edge tag, don't need to do anything with leading tabs here
            return """\
        <edge id="e{num}" source="{source}" target="{target}"/>\n""".format(num=num,
                                                                            source=source,
                                                                            target=target)

        nodes_queue.put(start_function_metadata)

        #
        # let's build the graph.
        # NOTE: during that traversal we will not add graph nodes (only edges)
        # information to the output data, because we need to collect the information
        # about all nodes first in order to calculate proper number of vertices of polygon,
        # which can be the shape of graph nodes. That's all because we want to distribute
        # the number of polygon vertices efficiently based on actual complexity of graph functions.
        # That's because GraphML edges and nodes generation is split into different functions
        #

        while not nodes_queue.empty():
            src_func_metadata = nodes_queue.get()
            if src_func_metadata in nodes_traversed:
                continue
            else:
                nodes_traversed.append(src_func_metadata)

            for dst_func_address in src_func_metadata.xrefs_to:
                dst_func_metadata = metadata.functions.get(dst_func_address)
                # don't have metadata or address doesn't point to function start address, skip it
                if dst_func_metadata is None:
                    continue

                # add GraphML edge to output data, using unique raw names as nodes ids
                graphml_edges_data += edge_wrapper(edges_num,
                                                   src_func_metadata.raw_name,
                                                   dst_func_metadata.raw_name)
                edges_num += 1
                nodes_queue.put(dst_func_metadata)

        return nodes_traversed, graphml_edges_data

    def _generate_graphml_nodes(self, graph_nodes):
        """
        Generate GraphML nodes data.
        """
        coverage = self._director.coverage

        # constants for polygon shapes vertices computation
        extreme_nodes_percentage = 0.05
        # disk has zero vertices, so...
        disk_shape = 0
        max_polygon_vertices = 8
        # value can't be lower than 3
        min_polygon_vertices = 3

        # the amount of a reachable code and the covered one
        reachable_instruction_count = 0
        instructions_covered = 0

        graphml_nodes_data = ""

        # nested function for nodes wrapping
        def node_wrapper(func_metadata, coverage_percentage, shape_vertices):
            # escape XML special characters in names
            escape_mapping = {"<": " &lt; ", ">": " &gt; ", "&": " &amp; "}
            escape_trans_table = func_metadata.raw_name.maketrans(escape_mapping)
            raw_name = func_metadata.raw_name.translate(escape_trans_table)
            escape_trans_table = func_metadata.name.maketrans(escape_mapping)
            name = func_metadata.name.translate(escape_trans_table)
            # we need two tabs indent for node tag, don't need to do anything with leading tabs here
            return """\
        <node id="{raw_name}">
            <data key="label">{name}</data>
            <data key="fsize">{fsize}</data>
            <data key="cov">{cov:.2f}</data>
            <data key="cc">{cc}</data>
            <data key="mem_ref">{mem_ref}</data>
            <data key="polygon">{polygon}</data>
        </node>\n""".format(raw_name=raw_name,
                            name=name,
                            fsize=func_metadata.size,
                            cov=coverage_percentage,
                            cc=func_metadata.cyclomatic_complexity,
                            mem_ref=func_metadata.read_refs_count + func_metadata.write_refs_count,
                            polygon=shape_vertices)

        # sort nodes by complexity to distribute the number of vertices in polygon-shaped nodes
        graph_nodes.sort(key=lambda function: function.cyclomatic_complexity)

        #
        # efficient distribution of nodes with some percentage of min and max "extreme" values
        #

        # take defined percentage of extreme complexity nodes for extreme number of polygon vertices
        extreme_nodes_num = int(len(graph_nodes) * extreme_nodes_percentage)
        if extreme_nodes_num > 0:

            #
            # to avoid the case when adjacent nodes with the same complexity have different
            # shapes we will increase extreme nodes num until adjacent nodes have the same
            # complexity
            #

            num = extreme_nodes_num
            while num < len(graph_nodes) and \
                    graph_nodes[num - 1].cyclomatic_complexity == graph_nodes[num].cyclomatic_complexity:
                num += 1
            # generate GraphML nodes for nodes with smallest complexity
            for func_metadata in graph_nodes[:num]:
                func_coverage = coverage.functions.get(func_metadata.address, self._blank_coverage)
                # add function as GraphML node to the output data
                graphml_nodes_data += node_wrapper(func_metadata,
                                                   func_coverage.instruction_percent * 100,
                                                   disk_shape)
                reachable_instruction_count += func_metadata.instruction_count
                instructions_covered += func_coverage.instructions_executed
            # delete extreme nodes from the list for convenience
            del graph_nodes[:num]
            if not graph_nodes:
                # return GraphML data together with the coverage percentage of a reachable code
                return float(instructions_covered) / reachable_instruction_count, graphml_nodes_data

            #
            # we need to check that max/min regions were not overlapped
            # during the addition of adjacent nodes to min region. As min nodes were deleted,
            # overlapping can be detected by checking that extreme_nodes_num is
            # greater than new length of graph_nodes
            #

            num = min(extreme_nodes_num, len(graph_nodes))
            # check adjacent nodes as for minimum region
            while num < len(graph_nodes) and \
                    graph_nodes[-num].cyclomatic_complexity == graph_nodes[-num - 1].cyclomatic_complexity:
                num += 1
            # generate GraphML nodes for nodes with largest complexity
            for func_metadata in graph_nodes[-num:]:
                func_coverage = coverage.functions.get(func_metadata.address, self._blank_coverage)
                # add function as GraphML node to the output data
                graphml_nodes_data += node_wrapper(func_metadata,
                                                   func_coverage.instruction_percent * 100,
                                                   max_polygon_vertices)
                reachable_instruction_count += func_metadata.instruction_count
                instructions_covered += func_coverage.instructions_executed
            max_polygon_vertices -= 1
            # delete extreme nodes from the list for convenience
            del graph_nodes[-num:]
            if not graph_nodes:
                # return GraphML data together with the coverage percentage of a reachable code
                return float(instructions_covered) / reachable_instruction_count, graphml_nodes_data

        #
        # efficient distribution of other nodes
        #

        min_complexity = graph_nodes[0].cyclomatic_complexity
        max_complexity = graph_nodes[-1].cyclomatic_complexity
        # chunks interval length, based on complexity min/max values
        complexity_interval = \
            (max_complexity - min_complexity) / (max_polygon_vertices - min_polygon_vertices + 1)
        cur_polygon_vertices = min_polygon_vertices
        cur_complexity_bound = min_complexity + complexity_interval
        for func_metadata in graph_nodes:
            # check that node is still inside current interval
            while func_metadata.cyclomatic_complexity > cur_complexity_bound:
                cur_polygon_vertices += 1
                cur_complexity_bound += complexity_interval

            func_coverage = coverage.functions.get(func_metadata.address, self._blank_coverage)
            # add function as GraphML node to the output data
            graphml_nodes_data += node_wrapper(func_metadata,
                                               func_coverage.instruction_percent * 100,
                                               cur_polygon_vertices)
            reachable_instruction_count += func_metadata.instruction_count
            instructions_covered += func_coverage.instructions_executed

        # return GraphML data together with the coverage percentage of a reachable code
        return float(instructions_covered) / reachable_instruction_count, graphml_nodes_data

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
            normalize = lambda x: x.lower()

        #
        # it's time to rebuild the list of coverage items to make visible in
        # the coverage overview list. during this process, we filter out entries
        # that do not meet the criteria as specified by the user.
        #

        # loop through *all* the functions as defined in the active metadata
        for function_address in metadata.functions:

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

        # add a special entry for 'orphan coverage'
        self.row2func[len(self.row2func)] = BADADDR

        # build the inverse func --> row mapping
        self.func2row = {v: k for k, v in iteritems(self.row2func)}

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
