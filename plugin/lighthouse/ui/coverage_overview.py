import idaapi
import logging
from PySide import QtGui, QtCore

logger = logging.getLogger("Lighthouse.UI.List")

#--------------------------------------------------------------------------
# Coverage Data Proxy Model
#--------------------------------------------------------------------------

class CoverageModel(QtCore.QAbstractItemModel):
    """
    TODO
    """

    def __init__(self, db_coverage, parent=None):
        super(CoverageModel, self).__init__(parent)
        self._db_coverage = None
        self.row2func = {}

        # green to red - 'light' theme
        #self._color_coverage_bad  = QtGui.QColor(207, 31, 0)
        #self._color_coverage_good = QtGui.QColor(75, 209, 42)

        # blue to red - 'dark' theme
        self._color_coverage_bad  = QtGui.QColor(221, 0, 0)
        self._color_coverage_good = QtGui.QColor(51, 153, 255)

        # headers of the table
        self._column_headers = \
        [
            "Coverage %",
            "Function Name",
            "Address",
            "Basic Blocks",
            "Branches",
            "Lines",
            ""                 # NOTE: stretch section, left blank for now
        ]

        # update the model with the given coverage data
        self.update_model(db_coverage)

    #----------------------------------------------------------------------
    # AbstractItemModel Overloads
    #----------------------------------------------------------------------

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
        return len(self._db_coverage.functions)

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

            # Coverage % - (by block taint)
            if index.column() == 0:
                return "%.2f%%" % (func_coverage.percent_node*100)

            # Function Name
            elif index.column() == 1:
                return func_coverage.name

            # Function Address
            elif index.column() == 2:
                return "0x%08X" % func_coverage.address

            # Basic Blocks
            elif index.column() == 3:
                return "%u / %u" % (len(func_coverage.nodes_tainted),
                                        func_coverage.nodes_total)

            # Branches
            elif index.column() == 4:
                return "TODO"

            # Lines
            elif index.column() == 5:
                return "TODO"

        # cell background color request
        elif role == QtCore.Qt.BackgroundRole:
            func_coverage = self.row2func[index.row()]

            # TODO/PERF: can we just bake this in the func coverage?
            # compute cell/row color
            row_color = compute_color_on_gradiant(
                func_coverage.percent_node,
                self._color_coverage_bad,
                self._color_coverage_good
            )

            return row_color

        # font color request
        elif role == QtCore.Qt.ForegroundRole:
            return QtGui.QColor(QtCore.Qt.white)

        return None

    #----------------------------------------------------------------------
    # Model Updates
    #----------------------------------------------------------------------

    def update_model(self, db_coverage):
        """
        Replace the underlying data source and re-generate model mappings.
        """
        self._db_coverage = db_coverage
        self._rebuild_row2func_map()

        # let consumers know that we have updated the model
        self.layoutChanged.emit()

    def _rebuild_row2func_map(self):
        """
        Rebuild the mapping to go from displayed row to function.
        """
        self.row2func = {}

        # no coverage, nothing else to do
        if not self._db_coverage:
            return

        # build new mapping of row to function
        row = 0
        for func_coverage in self._db_coverage.functions.itervalues():
            self.row2func[row] = func_coverage
            row += 1

#--------------------------------------------------------------------------
# Coverage Overview
#--------------------------------------------------------------------------

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
        self.parent = self.FormToPySideWidget(form)

        #
        # create & configure the list (technically tree)
        #

        self.coverage_list = QtGui.QTreeView()
        self.coverage_list.setExpandsOnDoubleClick(False)
        self.coverage_list.setRootIsDecorated(False)

        # install a delegate to draw the grid on the list view
        delegate = GridDelegate(self.coverage_list)
        self.coverage_list.setItemDelegate(delegate)

        # install the data source for the view
        self.coverage_list.setModel(self._model)

        #
        # signals
        #

        # connect a signal to jump to the function disas described by a row
        #self.coverage_list.doubleClicked.connect(self._ui_double_click)

        #
        # layout
        #

        # build layout
        layout = QtGui.QGridLayout()
        layout.addWidget(self.coverage_list)

        # install layout
        self.parent.setLayout(layout)

    def update_model(self, db_coverage):
        """
        Passthrough to update underlying model.
        """
        self._model.update_model(db_coverage)

    def _ui_double_click(self, index):
        """
        TODO
        """
        pass

#--------------------------------------------------------------------------
# Painting
#--------------------------------------------------------------------------

class GridDelegate(QtGui.QStyledItemDelegate):
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
