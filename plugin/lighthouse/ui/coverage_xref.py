import os
import logging

from lighthouse.util import lmsg
from lighthouse.util.qt import *
from lighthouse.util.misc import human_timestamp
from lighthouse.util.python import *

logger = logging.getLogger("Lighthouse.UI.Xref")

#------------------------------------------------------------------------------
# Coverage Xref Dialog
#------------------------------------------------------------------------------

class CoverageXref(QtWidgets.QDialog):
    """
    A Qt Dialog to list other coverage sets that contain a given address.

    This class makes up a rudimentary xref dialog. It does not follow Qt
    'best practices' because it does not need to be super flashy, nor does
    it demand much facetime.
    """

    def __init__(self, director, address):
        super(CoverageXref, self).__init__()
        self._director = director

        # dialog attributes
        self.address = address
        self.selected_coverage = None
        self.selected_filepath = None

        # configure the widget for use
        self._ui_init()

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """
        self.setWindowTitle("Coverage Xrefs to 0x%X" % self.address)
        self.setWindowFlags(self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)
        self.setModal(True)

        self._font = self.font()
        self._font.setPointSizeF(normalize_to_dpi(10))
        self._font_metrics = QtGui.QFontMetricsF(self._font)

        # initialize coverage xref table
        self._ui_init_table()
        self._populate_table()

        # layout the populated UI just before showing it
        self._ui_layout()

    def _ui_init_table(self):
        """
        Initialize the coverage xref table UI elements.
        """
        self._table = QtWidgets.QTableWidget()
        self._table.verticalHeader().setVisible(False)
        self._table.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self._table.horizontalHeader().setFont(self._font)
        self._table.setFont(self._font)
        self._table.setWordWrap(False)

        # symbol, cov %, name, time
        self._table.setColumnCount(4)
        self._table.setHorizontalHeaderLabels(["Sym", "Cov %", "Coverage Name", "Timestamp"])
        self._table.setColumnWidth(0, 45)
        self._table.setColumnWidth(1, 55)
        self._table.setColumnWidth(2, 400)
        self._table.setColumnWidth(3, 100)

        # left align text in column headers
        for i in range(4):
            self._table.horizontalHeaderItem(i).setTextAlignment(QtCore.Qt.AlignLeft)

        # disable bolding of column headers when selected
        self._table.horizontalHeader().setHighlightSections(False)

        # stretch the filename field, as it is the most important
        self._table.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)

        # make table read only, select a full row by default
        self._table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # catch double click events on table rows
        self._table.cellDoubleClicked.connect(self._ui_cell_double_click)

    def _populate_table(self):
        """
        Populate the xref table with data from the coverage director.
        """
        cov_xrefs = self._director.get_address_coverage(self.address)
        file_xrefs = self._director.get_address_file(self.address)

        # dedupe
        for coverage in cov_xrefs:
            if coverage.filepath in file_xrefs:
                file_xrefs.remove(coverage.filepath)

        # populate table with coverage details
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(cov_xrefs) + len(file_xrefs))

        # coverage objects
        for i, coverage in enumerate(cov_xrefs, 0):
            self._table.setItem(i, 0, QtWidgets.QTableWidgetItem(self._director.get_shorthand(coverage.name)))
            self._table.setItem(i, 1, QtWidgets.QTableWidgetItem("%5.2f" % (coverage.instruction_percent*100)))
            name_entry = QtWidgets.QTableWidgetItem(coverage.name)
            name_entry.setToolTip(coverage.filepath)
            self._table.setItem(i, 2, name_entry)
            date_entry = QtWidgets.QTableWidgetItem()
            date_entry.setData(QtCore.Qt.DisplayRole, QtCore.QDateTime.fromMSecsSinceEpoch(coverage.timestamp*1000))
            self._table.setItem(i, 3, QtWidgets.QTableWidgetItem(date_entry))

        # filepaths
        for i, filepath in enumerate(file_xrefs, len(cov_xrefs)):

            # try to read timestamp of the file on disk (if it exists)
            try:
                timestamp = os.path.getmtime(filepath)
            except (OSError, TypeError):
                timestamp = 0

            # populate table entry
            self._table.setItem(i, 0, QtWidgets.QTableWidgetItem("-"))
            self._table.setItem(i, 1, QtWidgets.QTableWidgetItem("-"))
            name_entry = QtWidgets.QTableWidgetItem(os.path.basename(filepath))
            name_entry.setToolTip(filepath)
            self._table.setItem(i, 2, name_entry)
            date_entry = QtWidgets.QTableWidgetItem()
            date_entry.setData(QtCore.Qt.DisplayRole, QtCore.QDateTime.fromMSecsSinceEpoch(timestamp*1000))
            self._table.setItem(i, 3, date_entry)

        self._table.resizeColumnsToContents()
        self._table.resizeRowsToContents()

        self._table.setSortingEnabled(True)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """
        layout = QtWidgets.QVBoxLayout()

        # layout child widgets
        layout.addWidget(self._table)

        # scale widget dimensions based on DPI
        height = get_dpi_scale() * 250
        width = get_dpi_scale() * 600
        self.setMinimumHeight(height)
        self.setMinimumWidth(width)

        # apply the widget layout
        self.setLayout(layout)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_cell_double_click(self, row, column):
        """
        A cell/row has been double clicked in the xref table.
        """
        if self._table.item(row, 0).text() == "-":
            self.selected_filepath = self._table.item(row, 2).toolTip()
        else:
            self.selected_coverage = self._table.item(row, 2).text()
        self.accept()
