import os
import logging

from lighthouse.util import lmsg
from lighthouse.util.qt import *
from lighthouse.util.misc import human_timestamp
from lighthouse.util.python import *

logger = logging.getLogger("Lighthouse.UI.ModuleSelector")

#------------------------------------------------------------------------------
# Coverage Xref Dialog
#------------------------------------------------------------------------------

class ModuleSelector(QtWidgets.QDialog):
    """
    A Qt Dialog to list all the coverage modules in a coverage file.

    This class makes up a rudimentary selector dialog. It does not follow Qt
    'best practices' because it does not need to be super flashy, nor does
    it demand much facetime.
    """

    def __init__(self, target_name, module_names, coverage_file):
        super(ModuleSelector, self).__init__()

        self._target_name = target_name
        self._module_names = module_names
        self._coverage_file = os.path.basename(coverage_file)

        # dialog attributes
        self.selected_name = None
        self.remember_alias = False

        # configure the widget for use
        self._ui_init()

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """
        self.setWindowTitle("Select module matching this database")
        self.setWindowFlags(self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)
        self.setModal(True)

        # initialize module selector table
        self._ui_init_header()
        self._ui_init_table()
        self._populate_table()

        # layout the populated UI just before showing it
        self._ui_layout()

    def _ui_init_header(self):
        """
        Initialize the module selector header UI elements.
        """

        description_text = \
        "Lighthouse could not automatically identify the target module in the given coverage file:<br />" \
        "<br />" \
        "-- <b>Target:</b> %s<br />" \
        "-- <b>Coverage File:</b> %s<br />" \
        "<br />" \
        "Please double click the name of the module that matches this database, or close this dialog<br />" \
        "if you do not see your binary listed in the table below..." % (self._target_name, self._coverage_file)

        self._label_description = QtWidgets.QLabel(description_text)
        self._label_description.setTextFormat(QtCore.Qt.RichText)
        #self._label_description.setWordWrap(True)

        # a checkbox to save the user selected alias to the database
        self._checkbox_remember = QtWidgets.QCheckBox("Remember target module alias for this session")

    def _ui_init_table(self):
        """
        Initialize the module selector table UI elements.
        """
        self._table = QtWidgets.QTableWidget()
        self._table.verticalHeader().setVisible(False)
        self._table.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)

        # Create a simple table / list
        self._table.setColumnCount(1)
        self._table.setHorizontalHeaderLabels(["Module Name"])

        # left align text in column headers
        self._table.horizontalHeaderItem(0).setTextAlignment(QtCore.Qt.AlignLeft)

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
        Populate the module table with the module names provided to this dialog.
        """
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(self._module_names))
        for i, module_name in enumerate(self._module_names, 0):
            self._table.setItem(i, 0, QtWidgets.QTableWidgetItem(module_name))
        self._table.resizeRowsToContents()
        self._table.setSortingEnabled(True)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """
        layout = QtWidgets.QVBoxLayout()
        #layout.setContentsMargins(0,0,0,0)

        # layout child widgets
        layout.addWidget(self._label_description)
        layout.addWidget(self._table)
        layout.addWidget(self._checkbox_remember)

        # scale widget dimensions based on DPI
        height = get_dpi_scale() * 250
        width = get_dpi_scale() * 400
        self.setMinimumHeight(height)
        self.setMinimumWidth(width)

        # apply the widget layout
        self.setLayout(layout)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_cell_double_click(self, row, column):
        """
        A cell/row has been double clicked in the module table.
        """
        self.selected_name = self._table.item(row, 0).text()
        self.remember_alias = self._checkbox_remember.isChecked()
        self.accept()
