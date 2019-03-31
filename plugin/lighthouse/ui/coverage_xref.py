import os
import time
import string
import logging

from lighthouse.util import lmsg
from lighthouse.util.qt import *
from lighthouse.util.python import *
from lighthouse.util.misc import mainthread
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.UI.Xref")

#------------------------------------------------------------------------------
# Coverage Xref Dialog
#------------------------------------------------------------------------------

class CoverageXref(QtWidgets.QDialog):
    def __init__(self, director, address):
        super(CoverageXref, self).__init__()
        self.director = director
        self.address = address
        self.selected_name = None
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
        #self.setWindowFlags(self.windowFlags() | QtCore.Qt.MSWindowsFixedSizeDialogHint)

        # configure the main widget / form
        #self.setSizeGripEnabled(False)
        self.setModal(True)
        self._dpi_scale = get_dpi_scale()*5.0

        # initialize coverage xref table
        self._build_table()

        # layout the populated UI just before showing it
        self._ui_layout()

    def _build_table(self):

        xrefs = self.director.xref_coverage(self.address)

        self._table = QtWidgets.QTableWidget(self)
        self._table.verticalHeader().setVisible(False)

        # symbol, cov %, name, time
        self._table.setColumnCount(4)
        self._table.setHorizontalHeaderLabels(["Sym", "Cov %", "Coverage Name", "Time"])
        self._table.setColumnWidth(0, 40)
        self._table.setColumnWidth(1, 50)
        self._table.setColumnWidth(2, 300)
        self._table.setColumnWidth(3, 200)

        # align text in table headers to the left
        for i in range(4):
            self._table.horizontalHeaderItem(i).setTextAlignment(QtCore.Qt.AlignLeft)

        # disable bolding of table headers when selected
        self._table.horizontalHeader().setHighlightSections(False)

        # stretch the last column of the table (aesthetics)
        self._table.horizontalHeader().setStretchLastSection(True)

        # make table read only, select a full row by default
        self._table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # populate table with coverage details
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(xrefs))
        for i, coverage in enumerate(xrefs, 0):
            self._table.setItem(i, 0, QtWidgets.QTableWidgetItem(self.director.get_shorthand(coverage.name)))
            self._table.setItem(i, 1, QtWidgets.QTableWidgetItem("%5.2f" % (coverage.instruction_percent*100)))
            self._table.setItem(i, 2, QtWidgets.QTableWidgetItem(coverage.name))
            self._table.setItem(i, 3, QtWidgets.QTableWidgetItem("%u (%s)" % (coverage.timestamp, coverage.human_timestamp)))
        self._table.setSortingEnabled(True)

        # signals
        self._table.cellDoubleClicked.connect(self._ui_cell_double_click)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0,0,0,0)

        # layout child widgets
        layout.addWidget(self._table)

        # scale widget dimensions based on DPI
        height = self._dpi_scale * 50
        self.setMinimumHeight(height)
        width = self._dpi_scale * 120
        self.setMinimumWidth(width)

        # apply the widget layout
        self.setLayout(layout)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_cell_double_click(self, row, column):
        """
        TODO
        """
        self.selected_name = self._table.item(row, 2).text()
        self.accept()
