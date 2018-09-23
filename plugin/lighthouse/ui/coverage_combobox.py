import logging
from lighthouse.util import *
from lighthouse.util.qt import *
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.UI.ComboBox")

#------------------------------------------------------------------------------
# Constants Definitions
#------------------------------------------------------------------------------

SEPARATOR = "seperator"
SEPARATOR_HEIGHT = 1 # pixels

ENTRY_USER    = "USER"
ENTRY_SPECIAL = "SPECIAL"

COLUMN_COVERAGE_STRING = 0
COLUMN_DELETE          = 1

#------------------------------------------------------------------------------
# Coverage ComboBox
#------------------------------------------------------------------------------

class CoverageComboBox(QtWidgets.QComboBox):
    """
    The Coverage ComboBox UI for switching between loaded coverage.

    I had to write an unnecessary amount of code to prototype the engaging
    combobox experiences I was looking for.

    But now that we have all the important combobox components subclassed
    out (it was necessary, I promise), perhaps there are a few more
    interesting and fun features we can add in the future.
    """

    def __init__(self, director, parent=None):
        super(CoverageComboBox, self).__init__(parent)
        self.setObjectName(self.__class__.__name__)
        self._director = director

        # configure the widget for use
        self._ui_init()

    #--------------------------------------------------------------------------
    # QComboBox Overloads
    #--------------------------------------------------------------------------

    def mousePressEvent(self, e):
        """
        Capture mouse click events to the QComboBox.
        """

        # get the widget currently beneath the given mouse event
        hovering = self.childAt(e.pos())

        #
        # if the hovered widget is the 'head' of the QComboBox, we want to
        # move any mouse clicks to appear like it was on the dropdown arrow
        # box on the right side.
        #
        # this is to satisfy some internal QComboBox Qt logic, allowing us
        # to collapse and expand an 'editable' QComboBox by clicking anywhere
        # on the 'head' (the read-only QLineEdit)
        #
        # this is basically dirty-hax
        #

        if hovering == self.lineEdit():
            new_pos = QtCore.QPoint(
                self.rect().right() - 10,
                self.rect().height()/2
            )
            logger.debug("Moved click %s --> %s" % (e.pos(), new_pos))
            e = move_mouse_event(e, new_pos)

        # handle the event (possibly moved) as it normally would be
        super(CoverageComboBox, self).mousePressEvent(e)

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """

        # initialize a monospace font to use with our widget(s)
        self._font = MonospaceFont()
        self._font.setPointSizeF(normalize_to_dpi(9))
        self._font_metrics = QtGui.QFontMetricsF(self._font)
        self.setFont(self._font)

        # create the underlying model & table to power the combobox dropwdown
        self.setModel(CoverageComboBoxModel(self._director, self))
        self.setView(CoverageComboBoxView(self.model(), self))

        #
        # in the interest of maintaining a more consistent cross-platform
        # style for the coverage combobox and its dropdown, we use an
        # 'editable' QComboBox with the 'Windows' Qt style.
        #
        # since we don't actually want the QCombobox to be editable, we
        # do everything we can to make it readonly / non-interfaceable.
        #

        self.setEditable(True)
        self.lineEdit().setFont(self._font)
        self.lineEdit().setReadOnly(True)    # text can't be edited
        self.lineEdit().setEnabled(False)    # text can't be selected
        self.setMaximumHeight(self._font_metrics.height()*1.75)

        #
        # the combobox will pick a size based on its contents when it is first
        # made visible, but we also make it is arbitrarily resizable for the
        # user to change and play with at their own leisure
        #

        self.setSizeAdjustPolicy(QtWidgets.QComboBox.AdjustToContentsOnFirstShow)
        self.setSizePolicy(QtWidgets.QSizePolicy.Ignored, QtWidgets.QSizePolicy.Ignored)

        #
        # the purpose of this stylesheet is to pad the visible selection text
        # in the combobox 'head' on first show. The reason being is that
        # without this, the text for the selected coverage will lapse behind
        # the combobox dropdown arrow (which is Qt by design???)
        #
        # I don't like the tail of the text disappearing behind this silly
        # dropdown arrow, therefore we pad the right side of the combobox.
        #

        self.setStyleSheet("QComboBox { padding: 0 2ex 0 2ex; }")

        # draw the QComboBox with a 'Windows'-esque style
        self.setStyle(QtWidgets.QStyleFactory.create("Windows"))

        # connect relevant signals
        self._ui_init_signals()

    def _ui_init_signals(self):
        """
        Connect UI signals.
        """

        # combobox selection was changed
        self.activated.connect(self._ui_selection_changed)

        # the 'X' / delete icon was clicked on a dropdown entry
        self.view().clicked.connect(self._ui_clicked_delete)

        # register for cues from the director
        self._director.coverage_switched(self._internal_refresh)
        self._director.coverage_modified(self._internal_refresh)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_clicked_delete(self, index):
        """
        Handle a click on the 'X' delete icon (cell) on a dropdown entry.
        """

        if not index.isValid():
            return

        #
        # the dropdown popup is actually a 2D table. column 0 is the detailed
        # coverage string, where column '1' is actually the delete 'X' icon.
        #
        # this is a sanity check to ensure that the clicked index is actually
        # the deletion column. It should not be possible for column 0 (the
        # detail string) to pass through here, as that will be captured by
        # the default combobox signal handlers.
        #
        # the reason the deletion column clicks can pass through is because
        # the model has technically marked their cells as 'un-selectable'
        # through the flags() overload.
        #

        assert index.column() == COLUMN_DELETE, "Unexpected Column (%u)" % index.column()

        #
        # using the table cell index that was clicked, we want to lookup the
        # coverage name that this 'X' icon/cell is associated with.
        #
        # we retrieve the associated coverage name from the 'UserRole' field
        # of the model using the clicked index. The 'UserRole' is a Qt field
        # we are free to store developer/misc data in
        #

        coverage_name = self.model().data(index, QtCore.Qt.UserRole)
        assert coverage_name

        # pass the deletion request onto the director to delete said coverage
        self._director.delete_coverage(coverage_name)

        # refresh the dropdown (it will remove the deleted entry from the UI)
        self.showPopup()

        #
        # I don't want there to be any entries highlighted after a deletion
        # event, (it looks weird) so clear the table/dropdown highlights now
        #

        # NOTE/COMPAT
        if USING_PYQT5:
            self.view().selectionModel().setCurrentIndex(
                QtCore.QModelIndex(),
                QtCore.QItemSelectionModel.ClearAndSelect
            )
        else:
            self.view().selectionModel().setCurrentIndex(
                QtCore.QModelIndex(),
                QtGui.QItemSelectionModel.ClearAndSelect
            )


        #
        # the deletion of an entry will shift all the entries beneath it up
        # by one. in this case, it is important we refresh the selection index
        # to reflect the director so that it stays correct.
        #

        self._refresh_selection()

    def _ui_selection_changed(self, row):
        """
        Handle selection change of coverage combobox.
        """

        # convert the combobox row index into a QModelIndex
        index = self.model().index(row, 0)

        # using the true index, lookup the coverage name for this selection
        coverage_name = self.model().data(index, QtCore.Qt.UserRole)

        # pass the user selection onto the director to change loaded coverage
        self._director.select_coverage(coverage_name)

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    def refresh(self):
        """
        Public refresh of the coverage combobox.
        """
        self._internal_refresh()

    @disassembler.execute_ui
    def _internal_refresh(self):
        """
        Internal refresh of the coverage combobox.
        """
        # refresh the comobobox internals
        self.model().refresh()
        self.view().refresh()

        #
        # now that the comobobox is fully up to date, select the item index
        # that matches the active coverage as per the director
        #

        self._refresh_selection()

    def _refresh_selection(self):
        """
        Refresh the coverage combobox selection.
        """

        # NOTE: we block any index change signals to stop unnecessary churn
        self.blockSignals(True)
        new_index = self.findData(self._director.coverage_name)
        self.setCurrentIndex(new_index)
        self.lineEdit().home(False)
        self.blockSignals(False)

#------------------------------------------------------------------------------
# Coverage ComboBox - TableView
#------------------------------------------------------------------------------

class CoverageComboBoxView(QtWidgets.QTableView):
    """
    The (internal) table view used for the Coverage ComboBox dropdown.
    """

    def __init__(self, model, parent=None):
        super(CoverageComboBoxView, self).__init__(parent)
        self.setObjectName(self.__class__.__name__)

        # install the given data model into the table view
        self.setModel(model)

        # initialize UI elements
        self._ui_init()

    #--------------------------------------------------------------------------
    # QTableView Overloads
    #--------------------------------------------------------------------------

    def leaveEvent(self, e):
        """
        Overload the mouse leave event.
        """

        #
        # this code mitigates a bug (feature?) where the last hovered index
        # of the table view was retaining its MouseOver flag internally. This
        # was keeping my 'X' icons highlighted if the mouse cursor left the
        # table while touching one of these cells last.
        #
        # we basically send a fake 'Hover Event' to the table viewport at an
        # invalid position so table clears any remaining hover flags.
        #

        event = QtGui.QHoverEvent(QtCore.QEvent.HoverLeave, QtCore.QPoint(-1,-1), QtCore.QPoint(-1,-1))
        QtWidgets.QApplication.sendEvent(self.viewport(), event)

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """
        palette = self.model()._director._palette

        # initialize a monospace font to use with our widget(s)
        self._font = MonospaceFont()
        self._font.setPointSizeF(normalize_to_dpi(9))
        self._font_metrics = QtGui.QFontMetricsF(self._font)
        self.setFont(self._font)

        # widget style
        self.setStyleSheet(
            "QTableView {"
            "  background-color: %s;" % palette.combobox_bg.name() +
            "  color: %s;" % palette.combobox_fg.name() +
            "  selection-background-color: %s;" % palette.combobox_selection_bg.name() +
            "  selection-color: %s;" % palette.combobox_selection_fg.name() +
            "  margin: 0; outline: none;"
            "} "
            "QTableView::item{ padding: 0.5ex; } "
            "QTableView::item:focus { padding: 0; }"
        )

        # hide dropdown table headers, and default grid
        self.horizontalHeader().setVisible(False)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)

        # let Qt automatically elide (...) long row text (coverage names)
        self.resizeColumnToContents(0)
        self.setTextElideMode(QtCore.Qt.ElideRight)
        self.setWordWrap(False)

        # more code-friendly, readable aliases
        vh = self.verticalHeader()
        hh = self.horizontalHeader()

        #
        # NOTE/COMPAT:
        # - set the coverage name column to be stretchy and as tall as the text
        # - make the 'X' icon column fixed width
        #

        if USING_PYQT5:
            hh.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
            hh.setSectionResizeMode(1, QtWidgets.QHeaderView.Fixed)
            vh.setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        else:
            hh.setResizeMode(0, QtWidgets.QHeaderView.Stretch)
            hh.setResizeMode(1, QtWidgets.QHeaderView.Fixed)
            vh.setResizeMode(QtWidgets.QHeaderView.ResizeToContents)

        vh.setMinimumSectionSize(0)

        # get the column width hint from the model for the 'X' delete column
        icon_column_width = self.model().headerData(
            COLUMN_DELETE,
            QtCore.Qt.Horizontal,
            QtCore.Qt.SizeHintRole
        )

        # set the 'X' delete icon column width to a fixed size based on the hint
        hh.resizeSection(COLUMN_DELETE, icon_column_width)

        # install a delegate to do some custom painting against the combobox
        self.setItemDelegate(ComboBoxDelegate())

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    def refresh(self):
        """
        Refresh the coverage combobox list order.
        """
        model = self.model() # alias for readability

        # merge the 'special' entries up until a seperator is found
        for row in xrange(model.rowCount()):

            #
            # if this row is not a user defined entry, we want to merge ('span')
            # its cells so there is no 'X' delete button column shown for it.
            #
            # this should apply to special rows such as the 'Hot Shell',
            # 'Aggregate', or the 'separator' indexes
            #

            if not model.data(model.index(row, 1), QtCore.Qt.DecorationRole):
                self.setSpan(row, 0, 1, model.columnCount())

            # this is a user entry, ensure there is no span present (clear it)
            else:
                self.setSpan(row, 0, 0, model.columnCount())

#------------------------------------------------------------------------------
# Coverage ComboBox - TableModel
#------------------------------------------------------------------------------

class CoverageComboBoxModel(QtCore.QAbstractTableModel):
    """
    The (internal) table model used for the Coverage ComboBox dropdown.
    """

    def __init__(self, director, parent=None):
        super(CoverageComboBoxModel, self).__init__(parent)
        self.setObjectName(self.__class__.__name__)
        self._director = director

        # our internal model
        self._entries = []
        self._seperator_index = 0

        # initialize a monospace font to use with our widget(s)
        self._font = MonospaceFont()
        self._font.setPointSizeF(normalize_to_dpi(9))
        self._font_metrics = QtGui.QFontMetricsF(self._font)

        # load the raw 'X' delete icon from disk
        delete_icon = QtGui.QPixmap(plugin_resource("icons/delete_coverage.png"))

        # compute the appropriate size for the deletion icon
        icon_height = self._font_metrics.height()*0.75
        icon_width  = icon_height

        # scale the icon as appropriate (very likely scaling it down)
        self._delete_icon = delete_icon.scaled(
            icon_width,
            icon_height,
            QtCore.Qt.KeepAspectRatio,
            QtCore.Qt.SmoothTransformation
        )

        # register for cues from the director
        self._director.coverage_created(self.refresh)
        self._director.coverage_deleted(self.refresh)

    #--------------------------------------------------------------------------
    # QAbstractTableModel Overloads
    #--------------------------------------------------------------------------

    def rowCount(self, parent=QtCore.QModelIndex()):
        """
        The number of dropdown rows.
        """
        return len(self._entries)

    def columnCount(self, parent=QtCore.QModelIndex()):
        """
        The nubmer of dropdown columns.

        | column[0]                 | column[1]
        +---------------------------+--------------------
        | detailed coverage string1 | 'X' (delete icon)
        | detailed coverage string2 | 'X' (delete icon)
         ...

        """
        return 2

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        """
        Define the properties of the the table rows & columns.
        """

        # table row property request
        if orientation == QtCore.Qt.Vertical:

            # row height size hint request
            if role == QtCore.Qt.SizeHintRole:

                # the separator 'row' has a special, 'thinner' row size
                if section == self._seperator_index:
                    return SEPARATOR_HEIGHT

                # all other rows should be at least as tall as their text
                else:
                    return self._font_metrics.height()

        # table column property request
        elif orientation == QtCore.Qt.Horizontal:

            # column width size hint request
            if role == QtCore.Qt.SizeHintRole:

                #
                # the column holding the 'X' delete icon should be small
                # and fixed width, therefore we are explicit in specifying
                # our own size hint for it.
                #
                # note that the icon size is used to hint the column width,
                # but multiplied by two. this is because we want the 'X'
                # icon to float and have some padding in its column.
                #

                if section == COLUMN_DELETE:
                    return self._delete_icon.size().width() * 2

        # unhandled request, nothing to do
        return None

    def data(self, index, role=QtCore.Qt.DisplayRole):
        """
        Define how Qt should access the underlying model data.
        """

        # sanity check the given index
        if not index.isValid() or \
           not (index.row()    < self.rowCount()) or \
           not (index.column() < self.columnCount()):
            return None

        # font format request
        if role == QtCore.Qt.FontRole:
            return self._font

        # text alignment request
        elif role == QtCore.Qt.TextAlignmentRole:
            return QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft

        # data display request
        elif role in [QtCore.Qt.DisplayRole, QtCore.Qt.EditRole]:
            if index.column() == COLUMN_COVERAGE_STRING and index.row() != self._seperator_index:
                return self._director.get_coverage_string(self._entries[index.row()])

        # tooltip
        elif role == QtCore.Qt.ToolTipRole:
            if index.column() == COLUMN_COVERAGE_STRING and index.row() != self._seperator_index:
                coverage = self._director.get_coverage(self._entries[index.row()])
                return coverage.filepath if coverage.filepath else ""
            elif index.column() == COLUMN_DELETE:
                return "Delete loaded coverage"

        # icon display request
        elif role == QtCore.Qt.DecorationRole:

            # the icon request is for the 'X' column
            if index.column() == COLUMN_DELETE:

                #
                # if the coverage entry is below the separator, it is a user
                # loaded coverage and should always be deletable
                #

                if index.row() > self._seperator_index:
                    return self._delete_icon

                #
                # as a special case, we allow the aggregate to have a clear
                # icon, which will clear all user loaded coverages
                #

                elif self._entries[index.row()] == "Aggregate":
                    return self._delete_icon

        # entry type request
        elif role == QtCore.Qt.AccessibleDescriptionRole:

            #
            # if the entry is ABOVE the separator index, it's a 'special'
            # entry, eg 'Hot Shell', 'New Composition', 'Aggregate'
            #

            if index.row() < self._seperator_index:
                return ENTRY_SPECIAL

            #
            # the entry IS the separator index
            #

            elif index.row() == self._seperator_index:
                return SEPARATOR

            #
            # if the entry is BELOW the separator index, it's a 'user'
            # entry, eg loaded coverage files, compositions, etc
            #

            else:
                return ENTRY_USER

        # entry coverage_name request
        elif role == QtCore.Qt.UserRole:
            return self._entries[index.row()]

        # unhandeled request, nothing to do
        return None

    def flags(self, index):
        """
        Item flags for the given entry index.
        """

        # the 'X' column is ENABLED, but not technically selectable
        if index.column() == COLUMN_DELETE:
            return QtCore.Qt.ItemIsEnabled

        # the separator should not be interactive in *any* way
        if index.row() == self._seperator_index:
            return QtCore.Qt.NoItemFlags

        # unhandeled request, pass through
        return super(CoverageComboBoxModel, self).flags(index)

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    def refresh(self):
        """
        Refresh the coverage combobox model data.
        """

        # extract all the names from the director with a shorthand symbol
        with_shorthand = []
        for name in self._director.coverage_names:
            if self._director.get_shorthand(name):
                with_shorthand.append(name)

        # re-populate the model entries
        self._entries  = []
        self._entries += list(self._director.special_names)
        self._entries += [SEPARATOR]
        self._entries += with_shorthand

        # save the index of the separator for easy reference
        self._seperator_index = self._entries.index(SEPARATOR)

        # notify any listeners that the model layout may have changed
        self.layoutChanged.emit()

#------------------------------------------------------------------------------
# Coverage ComboBox - Painting Delegate
#------------------------------------------------------------------------------

class ComboBoxDelegate(QtWidgets.QStyledItemDelegate):
    """
    Coverage ComboBox Painting Delegate

    Painting delegates can be used to augment the painting of a given
    widget or its items. In this case, we use it to customize the
    dropdown table in the Coverage ComboBox a bit more to our liking.
    """

    def __init__(self, parent=None):
        super(ComboBoxDelegate, self).__init__(parent)

        # painting property definitions
        self._grid_color = QtGui.QColor(0x909090)
        self._separator_color = QtGui.QColor(0x505050)

    def sizeHint(self, option, index):
        """
        Augmented entry sizeHint.
        """
        if index.data(QtCore.Qt.AccessibleDescriptionRole) == SEPARATOR:
            return QtCore.QSize(1, SEPARATOR_HEIGHT)
        return super(ComboBoxDelegate, self).sizeHint(option, index)

    def paint(self, painter, option, index):
        """
        Augmented entry painting.
        """

        # custom paint the 'grid line' beneath each coverage entry
        if index.data(QtCore.Qt.AccessibleDescriptionRole) == ENTRY_USER:
            painter.save()
            painter.setPen(self._grid_color)

            # draw the grid line beneath the current row (a coverage entry)
            tweak = QtCore.QPoint(0, 1) # 1px tweak provides better spacing
            painter.drawLine(
                option.rect.bottomLeft() + tweak,
                option.rect.bottomRight() + tweak
            )

            #
            # now we will re-draw the grid line *above* the current entry,
            # fixing a minor graphical bug where grid lines could disappear
            # after hovering over a row / entry
            #

            previous = index.sibling(index.row()-1, 0)
            painter.drawLine(
                option.rect.topLeft(),
                option.rect.topRight()
            )

            painter.restore()

        # custom paint the separator entry between special & normal coverage
        if index.data(QtCore.Qt.AccessibleDescriptionRole) == SEPARATOR:
            painter.save()
            painter.setPen(self._separator_color)
            painter.drawRect(
                option.rect
            )
            painter.restore()

            # nothing else to paint for the separator entry
            return

        # custom paint the 'X' icon where applicable
        if index.data(QtCore.Qt.DecorationRole):

            # get the icon data from the model
            pixmap = index.data(QtCore.Qt.DecorationRole)

            # center the draw rect in the middle of the 'X' column cell
            destination_rect = pixmap.rect()
            destination_rect.moveCenter(option.rect.center())

            # augment the icon pixmap to be grayed out (disabled) or colored
            # based on the mouse hover status of this index
            if not (option.state & QtWidgets.QStyle.State_MouseOver):
                pixmap = QtWidgets.QApplication.style().generatedIconPixmap(
                    QtGui.QIcon.Disabled,
                    pixmap,
                    QtWidgets.QStyleOption()
                )

            # draw the icon to the column
            painter.drawPixmap(destination_rect, pixmap)

            # nothing else to paint for the icon column entry
            return

        # pass through to the standard painting
        super(ComboBoxDelegate, self).paint(painter, option, index)
