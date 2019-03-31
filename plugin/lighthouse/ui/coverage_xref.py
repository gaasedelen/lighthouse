import logging

from lighthouse.util import lmsg
from lighthouse.util.qt import *
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
        self.selected_name = None

        # configure the widget for use
        self._ui_init()

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """
        self.setWindowTitle("Coverage xrefs to 0x%X" % self.address)
        self.setWindowFlags(self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)
        self.setModal(True)

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

        # symbol, cov %, name, time
        self._table.setColumnCount(4)
        self._table.setHorizontalHeaderLabels(["Sym", "Cov %", "Coverage Name", "Timestamp"])
        self._table.setColumnWidth(0, 40)
        self._table.setColumnWidth(1, 50)
        self._table.setColumnWidth(2, 300)
        self._table.setColumnWidth(3, 200)

        # left align text in column headers
        for i in range(4):
            self._table.horizontalHeaderItem(i).setTextAlignment(QtCore.Qt.AlignLeft)

        # disable bolding of column headers when selected
        self._table.horizontalHeader().setHighlightSections(False)

        # stretch the last column of the table (aesthetics)
        self._table.horizontalHeader().setStretchLastSection(True)

        # make table read only, select a full row by default
        self._table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # catch double click events on table rows
        self._table.cellDoubleClicked.connect(self._ui_cell_double_click)

    def _populate_table(self):
        """
        Populate the xref table with data from the coverage director.
        """
        xrefs = self._director.xref_coverage(self.address)

        # populate table with coverage details
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(xrefs))
        for i, coverage in enumerate(xrefs, 0):
            self._table.setItem(i, 0, QtWidgets.QTableWidgetItem(self._director.get_shorthand(coverage.name)))
            self._table.setItem(i, 1, QtWidgets.QTableWidgetItem("%5.2f" % (coverage.instruction_percent*100)))
            self._table.setItem(i, 2, QtWidgets.QTableWidgetItem(coverage.name))
            self._table.setItem(i, 3, QtWidgets.QTableWidgetItem("%u (%s)" % (coverage.timestamp, coverage.human_timestamp)))
        self._table.setSortingEnabled(True)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0,0,0,0)

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
        self.selected_name = self._table.item(row, 2).text()
        self.accept()
