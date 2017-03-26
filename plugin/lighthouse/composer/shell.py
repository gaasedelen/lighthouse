from lighthouse.util import *
from .parser import *

class ComposingLine(QtWidgets.QPlainTextEdit):
    """
    TODO
    """

    def __init__(self, parent=None):
        super(ComposingLine, self).__init__(parent)

        self._font = MonospaceFont()
        self._font_metrics = QtGui.QFontMetricsF(self._font)

        self.setFont(self._font)
        self.setWordWrapMode(QtGui.QTextOption.NoWrap)
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)

        LINE_PADDING = 6
        line_height = self._font_metrics.lineSpacing() + LINE_PADDING
        self.setFixedHeight(line_height)

    def keyPressEvent(self, e):
        """
        Overload of the Text Edit's key press event.
        """
        if e.key() == QtCore.Qt.Key_Return or \
           e.key() == QtCore.Qt.Key_Enter  or \
           e.key() == QtCore.Qt.Key_Tab:
            e.accept()
        #elif e.key() == QtCore.Qt.Key_Down:
        #    self.table.setFocus(QtCore.Qt.TabFocusReason)
        #    e.accept()
        else:
            super(ComposingLine, self).keyPressEvent(e)


class ComposingShell(QtWidgets.QWidget):
    """
    TODO
    """

    def __init__(self, director):
        super(ComposingShell, self).__init__()
        self.setObjectName(self.__class__.__name__)
        self._director = director

        # parser related members
        self._parser = CompositionParser()
        self._parser_error = None
        self._parsed_tokens = []

        # list of valid shorthand coverage symbols
        self._shorthand = []

        # initialize UI elements
        self._ui_init()

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """

        # initialize a monospace font for our ui elements to use
        self._font = MonospaceFont()
        self._font_metrics = QtGui.QFontMetricsF(self._font)

        # initialize our ui elements
        self._ui_init_shell()
        self._ui_init_completer()
        self._ui_init_signals()
        self._ui_layout()

    def _ui_init_completer(self):
        """
        Initialize the autocomplete UI elements.
        """

        # NOTE/COMPAT:
        if using_pyqt5():
            self._completer_model = QtCore.QStringListModel([])
        else:
            self._completer_model = QtGui.QStringListModel([])

        self._completer = QtWidgets.QCompleter(self)
        self._completer.setCompletionMode(QtWidgets.QCompleter.PopupCompletion)
        self._completer.setModelSorting(QtWidgets.QCompleter.CaseInsensitivelySortedModel)
        self._completer.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
        self._completer.setModel(self._completer_model)
        self._completer.setWrapAround(False)
        self._completer.popup().setFont(self._font)
        self._completer.setWidget(self._line)

    def _ui_init_shell(self):
        """
        Initialize the shell UI elements.
        """

        # composer label
        self._line_label = QtWidgets.QLabel("Composer")
        self._line_label.setStyleSheet("QLabel { margin: 0 1ex 0 1ex }")
        self._line_label.setFont(self._font)

        # composer line/shell
        self._line = ComposingLine()

    def _ui_init_signals(self):
        """
        Connect UI signals.
        """

        # text changed on the shell
        self._line.textChanged.connect(self._ui_text_changed)

        # cursor position changed on the shell
        self._line.cursorPositionChanged.connect(self._ui_cursor_pos_changed)

        # refresh on certain events from the director
        self._director.coverage_created(self.refresh)
        self._director.coverage_deleted(self.refresh)
        self._director.coverage_modified(self.refresh)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """
        layout = QtWidgets.QHBoxLayout()
        layout.setContentsMargins(0,0,0,0)
        layout.addWidget(self._line_label)
        layout.addWidget(self._line)

        # apply the widget layout
        self.setLayout(layout)

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    def refresh(self):
        """
        Refresh the shell context.
        """
        self._refresh_hint_list()

    def _refresh_hint_list(self):
        """
        Refresh the shell coverage hint.
        """

        # get the most recent coverage strings from the director
        detailed_strings = [self._director.get_coverage_string(x) for x in self._director.coverage_names]
        self._completer_model.setStringList(detailed_strings)
        self._shorthand = [x[0] for x in detailed_strings]

        # queue a UI hint if necessary
        self._ui_draw_hint()

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_cursor_pos_changed(self):
        """
        Line edit cursor position changed.
        """
        self._ui_draw_hint()

    def _ui_text_changed(self):
        """
        Line edit text changed.
        """
        text = self._line.toPlainText()

        try:

            # clear any previous parse attempts/failures
            self._parser_error = None

            # attempt to parse the user input against the composition grammar
            self._parsed_tokens, ast = self._parser.parse(text, self._shorthand)

            # parse success, inform the director of the new composition
            self._director.apply_composition(ast)

        # parse failure
        except ParseError as e:
            self._parser_error = e

            #
            # even though we failed to generate an AST that can be evaluated,
            # we want to save the list of tokens *successfully* parsed before
            # the error as they will be used for basic syntax highlighting.
            #

            self._parsed_tokens = e.parsed_tokens

        # queue a refresh of the coverage hintbox
        self._ui_draw_hint()

        #
        # ~ syntax highlighting ~
        #

        # the parse failed, so there will be invalid text to highlight
        if self._parser_error:
            self._color_invalid()

        # paint any valid tokens
        self._color_tokens()

        # done
        return

    #--------------------------------------------------------------------------
    # Coverage Hint
    #--------------------------------------------------------------------------

    def _ui_draw_hint(self):
        """
        Draw the coverage hint as applicable.
        """
        cursor_index = self._line.textCursor().position()
        text_token   = self._get_cursor_coverage_token(cursor_index)

        #
        # the user's text cursor is over the index that produced a parse error
        # (assuming there was one), we want to show a full hint list as to
        # what coverage options are available.
        #

        if self._parser_error and self._parser_error.error_index == cursor_index:

            #
            # if the parse failed because we expected a coverage token,
            # show the user the fuller coverage list
            #

            if self._parser_error.expected == TokenCoverageSingle:
                self._ui_show_hint()

        #
        # the user's text cursor is directly before or after a coverage token,
        # so show the details for the coverage matching that shorthand (the hint)
        #

        elif text_token and (text_token.type == "COVERAGE_TOKEN"):
            self._ui_show_hint(text_token.value)

        # the cursor is not over an index of interest, no reason to hint coverage
        else:
            self._ui_hide_hint()

        # done
        return

    def _ui_show_hint(self, prefix=''):
        """
        Show the completion hint popup at the shell's cursor position.

        Optionally, one can specify a prefix (eg, the shorthand 'A') to
        limit the list of coverage items hinted.
        """

        #
        # if the completer is already visible and showing the requested prefix,
        # then we have nothing to do. this will help mitigate refresh flickers
        #

        if self._completer.popup().isVisible() and \
            self._completer.completionPrefix() == prefix:
            return

        # if there was anything previously selected in the popup, clear it now
        self._completer.popup().clearSelection()

        # show only hints matching the given prefix
        #   eg: prefix = 'A' will show only entry 'A - 42.30% - drcov.8...'
        self._completer.setCompletionPrefix(prefix)

        # specify the position and size of the hint popup
        cr = self._line.cursorRect()
        cr.setWidth(self._completer.popup().sizeHintForColumn(0))

        # show the hint popup
        self._completer.complete(cr)
        self._completer.popup().repaint() # reduces Hot Shell flicker

    def _ui_hide_hint(self):
        """
        Hide the completion hint popup.
        """
        self._completer.popup().hide()

    def _get_cursor_coverage_token(self, index):
        """
        Get the coverage token touching the cursor (if there is one).
        """

        # iterate through the list of known tokens on the line edit / shell
        for text_token in self._parsed_tokens:

            # skip any non-coverage text tokens
            if not text_token.type == "COVERAGE_TOKEN":
                continue

            # if this coverage text token touches our cursor, return it
            if text_token.span[0] <= index <= text_token.span[1]:
                return text_token

        # no coverage token on either side of the cursor
        return None

    #--------------------------------------------------------------------------
    # Syntax Highlighting
    #--------------------------------------------------------------------------

    def _color_tokens(self):
        """
        Highlight the valid composition tokens.
        """
        text = self._line.toPlainText()
        TOKEN_COLORS = self._director._palette.TOKEN_COLORS

        # alias the edit cursor, and save its original position
        cursor = self._line.textCursor()
        cursor_position = cursor.position()

        # setup the red highlighter
        highlight = QtGui.QTextCharFormat()
        highlight.setFontWeight(QtGui.QFont.Bold)

        self._line.blockSignals(True)
        ################# UPDATES DISABLED #################

        # paint every parsed token
        for token in self._parsed_tokens:

            # no style defined for this token, nothing to do
            if token.type not in TOKEN_COLORS:
                continue

            # alias the start and end of the text token
            token_start, token_end = token.span

            # select the token text
            cursor.setPosition(token_start, QtGui.QTextCursor.MoveAnchor)
            cursor.setPosition(token_end,   QtGui.QTextCursor.KeepAnchor)

            # delete the existing token text
            cursor.removeSelectedText()

            # insert a highlighted version of the token text
            #highlight.setBackground(QtGui.QBrush(QtGui.QColor(TOKEN_COLORS[token.type])))
            highlight.setForeground(QtGui.QBrush(QtGui.QColor(TOKEN_COLORS[token.type])))
            cursor.setCharFormat(highlight)
            cursor.insertText(token.value)

        # reset the cursor position & style
        cursor.setPosition(cursor_position)
        cursor.setCharFormat(QtGui.QTextCharFormat())
        self._line.setTextCursor(cursor)

        ################# UPDATES ENABLED #################
        self._line.blockSignals(False)

    def _color_invalid(self):
        """
        Highlight the invalid (un-parsable) text.
        """
        assert self._parser_error
        text = self._line.toPlainText()

        # the invalid text starts from the token that caused a parse error
        invalid_start = self._parser_error.error_index
        invalid_text  = text[invalid_start:]

        # no invalid text? nothing to highlight I guess
        if not invalid_text:
            return

        # alias the user cursor, and save its original position
        cursor = self._line.textCursor()
        cursor_position = cursor.position()

        # setup the invalid text highlighter
        invalid_color = self._director._palette.invalid_text
        highlight = QtGui.QTextCharFormat()
        highlight.setFontWeight(QtGui.QFont.Bold)
        highlight.setBackground(QtGui.QBrush(QtGui.QColor(invalid_color)))

        self._line.blockSignals(True)
        ################# UPDATES DISABLED #################

        # select the invalid text
        cursor.setPosition(invalid_start, QtGui.QTextCursor.MoveAnchor)
        cursor.setPosition(len(text), QtGui.QTextCursor.KeepAnchor)

        # delete the invalid text
        cursor.removeSelectedText()

        # insert a highlighted version of the invalid text
        cursor.setCharFormat(highlight)
        cursor.insertText(invalid_text)

        # reset the cursor position & style
        cursor.setPosition(cursor_position)
        cursor.setCharFormat(QtGui.QTextCharFormat())
        self._line.setTextCursor(cursor)

        ################# UPDATES ENABLED #################
        self._line.blockSignals(False)
