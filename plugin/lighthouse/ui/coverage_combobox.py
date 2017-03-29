import logging
from lighthouse.util import *

logger = logging.getLogger("Lighthouse.UI.ComboBox")

#------------------------------------------------------------------------------
# Coverage ComboBox
#------------------------------------------------------------------------------

class CoverageComboBox(QtWidgets.QComboBox):
    """
    TODO
    """

    def __init__(self, director, parent=None):
        super(CoverageComboBox, self).__init__(parent)
        self.setObjectName(self.__class__.__name__)
        self._director = director

        self._deleted_coverage = False

        # initialize UI elements
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

        # create the underlying model & table to power the combobox dropwdown
        self.setModel(CoverageComboBoxModel(self._director))
        self.setView(CoverageComboBoxView(self.model()))

        #
        # the combobox will pick a size based on its contents when it is first
        # made visible, but we also make it arbitrarily resizable for the user
        # to change at their own leisure
        #

        self.setSizeAdjustPolicy(QtWidgets.QComboBox.AdjustToContentsOnFirstShow)
        self.setSizePolicy(QtWidgets.QSizePolicy.Ignored, QtWidgets.QSizePolicy.Ignored)

        # connect relevant signals
        self._ui_init_signals()

    def _ui_init_signals(self):
        """
        Connect UI signals.
        """

        # combobox selection was changed
        self.activated.connect(self._ui_selection_changed)
        self.view().clicked.connect(self._ui_clicked_delete)

        # register for cues from the director
        self._director.coverage_switched(self.refresh)
        self._director.coverage_modified(self.refresh)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_clicked_delete(self, index):
        """
        Handle click on the 'X' deletion cell of a dropdown entry.
        """

        # using the table cell index, lookup the coverage name for this 'X'
        coverage_name = self.model().data(index, QtCore.Qt.UserRole)

        # sanity check
        assert (index.column() and coverage_name)

        # pass the deletion request onto the director to delete said coverage
        self._director.delete_coverage(coverage_name)

        # refresh the visible popup (removing the deleted entry from the list)
        self.showPopup()

        # I don't want there to be any entries highlighted after a deletion,
        # (it looks weird) so clear the table/dropdown selections now
        self.view().selectionModel().setCurrentIndex(
            QtCore.QModelIndex(),
            QtGui.QItemSelectionModel.ClearAndSelect
        )

    def _ui_selection_changed(self, _):
        """
        Handle selection change of coverage combobox.
        """
        assert len(self.view().selectedIndexes()) == 1

        # get the selected 2D table index that presumably triggered this event
        index = self.view().selectedIndexes()[0]

        # using the true index, lookup the coverage name for this selection
        coverage_name = self.model().data(index, QtCore.Qt.UserRole)

        # pass the user selection onto the director to change loaded coverage
        self._director.select_coverage(coverage_name)

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    def refresh(self):
        """
        Refresh the coverage combonox.
        """

        # refresh the comobobox internals
        self.model().refresh()
        self.view().refresh()

        #
        # now that the comobobox is fully up to date, select the item index
        # that matches the active coverage as per the director
        #

        # NOTE: we block any index change signals to stop unecessary churn
        self.blockSignals(True)
        new_index = self.findData(self._director.coverage_name)
        self.setCurrentIndex(new_index)
        self.blockSignals(False)

#------------------------------------------------------------------------------
# Coverage ComboBox - TableView
#------------------------------------------------------------------------------

class CoverageComboBoxView(QtWidgets.QTableView):
    """
    TODO
    """

    def __init__(self, model, parent=None):
        super(CoverageComboBoxView, self).__init__(parent)
        self.setObjectName(self.__class__.__name__)
        self.setModel(model)

        # initialize UI elements
        self._ui_init()

    def leaveEvent(self, e):
        """
        Bro, don't ask.
        """
        event = QtGui.QHoverEvent(QtCore.QEvent.HoverLeave, QtCore.QPoint(-1,-1), QtCore.QPoint(-1,-1))
        QtGui.QApplication.sendEvent(self.viewport(), event)

    def refresh(self):
        self.setSpan(0,0,1,self.model().columnCount())
        self.setSpan(1,0,1,self.model().columnCount())
        self.setSpan(2,0,1,self.model().columnCount())
        self.setSpan(3,0,1,self.model().columnCount())

    def _ui_init(self):
        """
        Initialize UI elements.
        """

        # initialize a monospace font to use with our widget(s)
        self._font = MonospaceFont()
        self._font_metrics = QtGui.QFontMetricsF(self._font)
        self.setFont(self._font)

        # TODO
        icon_size = (self._font_metrics.height(), self._font_metrics.height())

        self.horizontalHeader().setVisible(False)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)
        self.resizeRowToContents(True)

        #
        # NOTE/COMPAT:
        # - set the coverage name column to be stretchy and as tall as the text
        # - make the 'X' icon column fixed width
        #

        if using_pyqt5():
            # TODO
            pass
        else:
            self.horizontalHeader().setResizeMode(0, QtWidgets.QHeaderView.Stretch)
            self.horizontalHeader().setResizeMode(1, QtWidgets.QHeaderView.Fixed)
            self.verticalHeader().setResizeMode(QtWidgets.QHeaderView.ResizeToContents)
            self.verticalHeader().setMinimumSectionSize(0)

        # set the 'X' icon column width to that of the icon
        self.horizontalHeader().setDefaultSectionSize(icon_size[0])
        self.model()._delete_icon = self.model()._delete_icon.scaled(icon_size[0]/2, icon_size[1]/2, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)

        self.setItemDelegate(ComboBoxDelegate())

#------------------------------------------------------------------------------
# Coverage ComboBox - TableModel
#------------------------------------------------------------------------------

class CoverageComboBoxModel(QtCore.QAbstractTableModel):
    """
    TODO
    """

    def __init__(self, director, parent=None):
        super(CoverageComboBoxModel, self).__init__()
        self._director = director

        # our internal model
        self._strings = []
        self._special = [0,1,2,3]

        # TODO
        self._delete_icon = QtGui.QPixmap(resource_file("icons/delete_coverage.png"))

        # initialize a monospace font to use with our widget(s)
        self._font = MonospaceFont()
        self._font_metrics = QtGui.QFontMetricsF(self._font)
        self._row_height = self._font_metrics.height()

        # register for cues from the director
        self._director.coverage_created(self.refresh)
        self._director.coverage_deleted(self.refresh)

    def remove_name(self, coverage_name):
        self._strings.remove(coverage_name)
        self.layoutChanged.emit()

    def refresh(self):
        self._strings  = []
        self._strings += list(self._director.special_names)
        self._strings += ["separator"]
        self._strings += list(self._director.coverage_names)
        self.layoutChanged.emit()

    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self._strings)

    def columnCount(self, parent=QtCore.QModelIndex()):
        return 2

    def headerData(self, row, orientation, role=QtCore.Qt.DisplayRole):
        """
        Define the properties of how the table header should be displayed.
        """

        if orientation == QtCore.Qt.Vertical:
            if role == QtCore.Qt.SizeHintRole:
                if self._strings[row] == "seperator":
                    return QtCore.QSize(5, 7)
                else:
                    return self._row_height
        return None

    def data(self, index, role=QtCore.Qt.DisplayRole):
        """
        Define how Qt should access the underlying model data.
        """

        if not index.isValid():
            return None

        if index.row() >= len(self._strings):
            return None

        # font format request
        if role == QtCore.Qt.FontRole:
            return self._font

        # text alignment request
        elif role == QtCore.Qt.TextAlignmentRole:
            return QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft

        # data display request
        elif role == QtCore.Qt.DisplayRole:
            if index.column() == 0 and self._strings[index.row()] != "separator":
                return self._director.get_coverage_string(self._strings[index.row()])

        # 'X' icon data request
        elif role == QtCore.Qt.DecorationRole:
            if index.column() == 1 and index.row() not in self._special:
                return self._delete_icon

        elif role == QtCore.Qt.AccessibleDescriptionRole:
            return self._strings[index.row()]

        elif role == QtCore.Qt.UserRole:
            return self._strings[index.row()]

        return None

    def flags(self, index):
        """
        TODO
        """

        # make the 'X' column not technically selectable
        if index.column() == 1:
            return QtCore.Qt.ItemIsEnabled
        return super(CoverageComboBoxModel, self).flags(index)

#------------------------------------------------------------------------------
# Coverage ComboBox - Painting Delegate
#------------------------------------------------------------------------------

class ComboBoxDelegate(QtWidgets.QStyledItemDelegate):
    """
    TODO
    """

    def __init__(self, parent=None):
        super(ComboBoxDelegate, self).__init__(parent)
        self.grid_color = QtGui.QColor(0x505050)
        self.separator_color = QtGui.QColor(0x909090)
        self.padding = 3

    def sizeHint(self, option, index):
        if index.data(QtCore.Qt.AccessibleDescriptionRole) == "separator":
            return QtCore.QSize(1, 5)
        return super(ComboBoxDelegate, self).sizeHint(option, index)

    def paint(self, painter, option, index):

        rect = option.rect

        if index.row() > 3:
            painter.save()
            painter.setPen(self.grid_color)
            painter.drawLine(rect.bottomLeft(), rect.bottomRight())
            painter.restore()

        # perform custom painting for the separator
        if index.data(QtCore.Qt.AccessibleDescriptionRole) == "separator":
            painter.save()
            painter.setPen(self.separator_color)
            painter.drawLine(option.rect.left() +self.padding, option.rect.center().y(),
                             option.rect.right()-self.padding, option.rect.center().y())
            painter.restore()

        elif index.data(QtCore.Qt.DecorationRole):
            pixmap = index.data(QtCore.Qt.DecorationRole)
            p_rect = pixmap.rect()
            p_rect.moveCenter(rect.center())

            # draw disabled/enabled
            if not (option.state & QtGui.QStyle.State_MouseOver):
                pixmap = QtWidgets.QApplication.style().generatedIconPixmap(QtGui.QIcon.Disabled, pixmap, QtGui.QStyleOption())

            painter.drawPixmap(p_rect, pixmap)

        # perform standard painting for everything else
        else:
            super(ComboBoxDelegate, self).paint(painter, option, index)
