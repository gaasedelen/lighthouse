from .parser import *
from lighthouse.util import *
from lighthouse.util.qt import *
from lighthouse.util.disassembler import disassembler

#------------------------------------------------------------------------------
# Composing Shell
#------------------------------------------------------------------------------

class ComposingShell(QtWidgets.QWidget):
    """
    The ComposingShell UI for interactive coverage composition.

    This class ties together all the individual components that make up
    the Composing Shell, wrapping it up in a nice portable widget. This
    includes the label sitting at the head of the shell, the text box
    (the shell, a.k.a ComposingLine), and the composition parser.

    In theory, multiple ComposingShell objects could be instantiated and
    placed in various dialogs, forms, views, etc. These shells are fairly
    independent, but obviously must communicate with the director.
    """

    def __init__(self, director, table_model, table_view=None):
        super(ComposingShell, self).__init__()
        self.setObjectName(self.__class__.__name__)

        # external entities
        self._director = director
        self._palette = director._palette
        self._table_model = table_model
        self._table_view = table_view

        # command / input
        self._search_text = ""
        self._command_timer = QtCore.QTimer()

        # the last known user AST
        self._last_ast = None

        # composition parser related members
        self._parser = CompositionParser()
        self._parser_error = None
        self._parsed_tokens = []
        self._shorthand = []

        # configure the widget for use
        self._ui_init()

    #--------------------------------------------------------------------------
    # Properties
    #--------------------------------------------------------------------------

    @property
    def text(self):
        """
        The existing shell text.
        """
        return str(self._line.toPlainText())

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

        # initialize our ui elements
        self._ui_init_shell()
        self._ui_init_completer()
        self._ui_init_signals()
        self._ui_layout()

    def _ui_init_shell(self):
        """
        Initialize the shell UI elements.
        """

        # the composer label at the head of the shell
        self._line_label = QtWidgets.QLabel("Composer")
        self._line_label.setStyleSheet("QLabel { margin: 0 1ex 0 1ex }")
        self._line_label.setAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignHCenter)
        self._line_label.setFont(self._font)
        self._line_label.setFixedWidth(self._line_label.sizeHint().width())

        # the text box / shell / ComposingLine
        self._line = ComposingLine()

        # configure the shell background & default text color
        palette = self._line.palette()
        palette.setColor(QtGui.QPalette.Base, self._palette.overview_bg)
        palette.setColor(QtGui.QPalette.Text, self._palette.composer_fg)
        palette.setColor(QtGui.QPalette.WindowText, self._palette.composer_fg)
        self._line.setPalette(palette)

    def _ui_init_completer(self):
        """
        Initialize the coverage hint UI elements.
        """

        # NOTE/COMPAT:
        if USING_PYQT5:
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
        self._completer.popup().setStyleSheet(
            "background: %s;" % self._palette.shell_hint_bg.name() +
            "color: %s;" % self._palette.shell_hint_fg.name()
        )
        self._completer.setWidget(self._line)

    def _ui_init_signals(self):
        """
        Connect UI signals.
        """

        # text changed in the shell
        self._line.textChanged.connect(self._ui_shell_text_changed)

        # cursor position changed in the shell
        self._line.cursorPositionChanged.connect(self._ui_shell_cursor_changed)

        # return key pressed in the shell
        self._line.returnPressed.connect(self._ui_shell_return_pressed)

        # register for cues from the director
        self._director.coverage_created(self._internal_refresh)
        self._director.coverage_deleted(self._internal_refresh)
        self._director.coverage_modified(self._internal_refresh)

        # register for cues from the model
        self._table_model.layoutChanged.connect(self._ui_shell_text_changed)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """

        # create a qt layout for the 'composer' (the shell)
        layout = QtWidgets.QHBoxLayout()
        layout.setContentsMargins(0,0,0,0)

        #
        # Shell Layout:
        #   [ [ 'Composer' ][ ComposingLine                  ... ] ]
        #

        layout.addWidget(self._line_label)
        layout.addWidget(self._line)

        # apply the widget layout
        self.setLayout(layout)

    #--------------------------------------------------------------------------
    # Refresh
    #--------------------------------------------------------------------------

    def refresh(self):
        """
        Public refresh of the shell.
        """
        self._internal_refresh()

    @disassembler.execute_ui
    def _internal_refresh(self):
        """
        Internal refresh of the shell.
        """
        self._refresh_hint_list()

    def _refresh_hint_list(self):
        """
        Refresh the shell coverage hint contents.
        """
        hints = []
        self._shorthand = []

        # get the detailed coverage strings from the director
        for x in self._director.coverage_names:
            hints.append(self._director.get_coverage_string(x))
            symbol = self._director.get_shorthand(x)
            if symbol:
                self._shorthand.append(symbol)

        # install the fresh coverage strings to the hint completer dialog
        self._completer_model.setStringList(hints)

        # queue a UI coverage hint if necessary
        self._ui_hint_coverage_refresh()

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_hint_tooltip(self, text, index):
        """
        Display a non-intrusive error tooltip to the user.
        """

        #
        # hide the coverage hint if it is visible. things can look cluttered
        # down by the shell if we're trying to show both.
        #

        self._ui_hint_coverage_hide()

        # create a cursor and move it to the parse error location on the shell
        cursor_tip = QtGui.QTextCursor(self._line.document())
        cursor_tip.setPosition(index)

        #
        # using our carefully positioned cursor, we can now extract the relative
        # pixel position of the parse error on the shell and map its global
        # (absolute) pixel position on the screen.
        #

        position = self._line.mapToGlobal(self._line.cursorRect(cursor_tip).topLeft())

        # draw the tooltip at the computed parse error position
        x = QtWidgets.QToolTip.showText(position, text)

    def _ui_shell_cursor_changed(self):
        """
        Cursor position changed in the shell.
        """
        self._ui_hint_coverage_refresh()

    def _ui_shell_text_changed(self):
        """
        Text changed in the shell.
        """
        text = self.text

        #
        # a Search, eg '/DnsParse_'
        #

        if self.is_search(text):
            self._execute_search(text)
            self._highlight_search()
            return

        # not a search query clear any lingering filters for it
        else:
            self._table_model.filter_string("")

        #
        # a Jump, eg '0x804010a' or 'sub_1400016F0'
        #

        if self.is_jump(text) and self._table_view:
            self._line_label.setText("Jump")
            self._highlight_jump()
            return

        #
        # a Composition, eg '(A | B) - C'
        #

        self._execute_composition(text)
        self._highlight_composition()
        self._ui_hint_coverage_refresh()

    def _ui_shell_return_pressed(self):
        """
        Return / Enter pressed in the shell.

        The user pressed 'enter' in the shell, this means we want to try
        and save their composition as a new coverage set to the director.
        """
        text = self.text

        # a search query has no accept state, nothing to do
        if self.is_search(text):
            return

        # jump to the function entry containing the requested address
        if self.is_jump(text) and self._table_view:
            self._execute_jump(text)
            return

        # attempt to save the user crafted composition
        self._accept_composition()

    #--------------------------------------------------------------------------
    # Search
    #--------------------------------------------------------------------------

    @staticmethod
    def is_search(text):
        """
        Check if a string (text) looks like a search query.

        A search query is used to filter functions listed in the coverage
        overview table based on their name.

        eg: text = '/DnsParse_'
        """
        return (text and text[0] == "/")

    def _execute_search(self, text):
        """
        Execute the search semantics.
        """
        self._search_text = text[1:]

        #
        # if the user input is only "/" (starting to type something), hint
        # that they are entering the Search mode. nothing else to do!
        #

        if text == "/":
            self._line_label.setText("Search")
            return

        #
        # stop an existing command timer if there is one running. we are about
        # to schedule a new one or execute inline. so the old/deferred command
        # is no longer needed.
        #

        self._command_timer.stop()

        #
        # if the functions list is HUGE, we want to defer the filtering until
        # we think the user has stopped typing as each pass may take awhile
        # to compute (while blocking the main thread...)
        #

        if self._director.metadata.is_big():
            self._command_timer = singleshot(1000, self._execute_search_internal)
            self._command_timer.start()

        #
        # the database is not *massive*, let's execute the search immediately
        #

        else:
            self._execute_search_internal()

        # done
        return

    def _execute_search_internal(self):
        """
        Execute the actual search filtering & coverage metrics.
        """

        # the given text is a real search query, apply it as a filter now
        self._table_model.filter_string(self._search_text)

        # compute coverage % of the visible (filtered) results
        percent = self._table_model.get_modeled_coverage_percent()

        # show the coverage % of the search results in the shell label
        self._line_label.setText("%1.2f%%" % percent)

    def _highlight_search(self):
        """
        Syntax highlight a search query.
        """

        self._line.setUpdatesEnabled(False)
        ################# UPDATES DISABLED #################

        # clear any existing text colors
        self._color_clear()

        # color search based on if there are any matching results
        if self._table_model.rowCount():
            self._color_text(self._palette.valid_text, start=1)
        else:
            self._color_text(self._palette.invalid_text, start=1)

        ################# UPDATES ENABLED #################
        self._line.setUpdatesEnabled(True)

        # done
        return

    #--------------------------------------------------------------------------
    # Jump
    #--------------------------------------------------------------------------

    def is_jump(self, text):
        """
        Check if a string (text) looks like a jump query.

        A jump query is used to jump to a function in the coverage overview
        table based on their address.

        eg: text = '0x8040100', or 'sub_1400016F0'
        """
        return self._compute_jump(text) != 0

    def _compute_jump(self, text):
        """
        Compute the function address destination of a jump target from a string.

        eg: text = '0x8040100', or 'sub_8040100' --> jump to function 0x8040100
        """
        text = text.strip()

        #
        # if the user input is less than two characters, we automatically
        # dismiss it as a valid jump target. the primary reasons for this
        # is to avoid possible shorthand parsing clashes.
        #
        # eg: imagine the user has a valid function named 'A' that they want to
        # jump to - well we actually choose to ignore that request here.
        #
        # We favor the importance of shorthand symbols as used in compositions.
        #

        if len(text) < 2:
            return 0

        #
        # attempt to convert the user input from a hex number eg '0x8040105'
        # to its corresponding function address validated by the director
        #

        try:
            address = int(text, 16)
        except ValueError:
            pass
        else:
            function_metadata = self._director.metadata.get_function(address)
            if function_metadata:
                return function_metadata.address

        #
        # the user string did not translate to a parsable hex number (address)
        # or the function it falls within could not be found in the director.
        #
        # attempt to convert the user input from a function name, eg 'main',
        # or 'sub_1400016F0' to a function address validated by the director.
        #

        # special case to make 'sub_*' prefixed user inputs case insensitive
        if text.lower().startswith("sub_"):
            text = "sub_" + text[4:].upper()

        # look up the text function name within the director's metadata
        function_metadata = self._director.metadata.get_function_by_name(text)
        if function_metadata:
            return function_metadata.address

        #
        # the user string did not translate to a function name that could
        # be found in the director.
        #

        # failure, the user input (text) isn't a jump ...
        return 0

    def _execute_jump(self, text):
        """
        Execute the jump semantics.
        """
        assert self._table_view

        # retrieve the jump target
        function_address = self._compute_jump(text)
        assert function_address

        # select the function entry in the coverage overview table
        self._table_view.selectRow(self._table_model.func2row[function_address])
        self._table_view.scrollTo(
            self._table_view.currentIndex(),
            QtWidgets.QAbstractItemView.PositionAtCenter
        )

    def _highlight_jump(self):
        """
        Syntax highlight a jump query.
        """

        self._line.setUpdatesEnabled(False)
        ################# UPDATES DISABLED #################

        # clear any existing text colors
        self._color_clear()

        # color jump
        self._color_text(self._palette.valid_text)

        ################# UPDATES ENABLED #################
        self._line.setUpdatesEnabled(True)

        # done
        return

    #--------------------------------------------------------------------------
    # Composition
    #--------------------------------------------------------------------------

    def _execute_composition(self, text):
        """
        Execute a composition query.
        """

        # reset the shell head text
        self._line_label.setText("Composer")

        # attempt to parse & execute a composition
        try:

            # clear any previous parse attempts/failures
            self._parser_error = None

            # attempt to parse the user input against the composition grammar
            self._parsed_tokens, ast = self._parser.parse(text, self._shorthand)

            # if the AST changed since the last parse, inform the director
            if not ast_equal(self._last_ast, ast):
                self._director.cache_composition(ast)

            # save the newly parsed ast
            self._last_ast = ast

        # parse failure
        except ParseError as e:
            self._parser_error = e

            #
            # even though we failed to generate an AST that can be evaluated
            # by the director, we still want to save the list of tokens parsed.
            # these tokens will still be used for basic syntax highlighting.
            #

            self._parsed_tokens = e.parsed_tokens

        # done
        return True

    def _highlight_composition(self):
        """
        Syntax highlight a composition.
        """

        self._line.setUpdatesEnabled(False)
        ################# UPDATES DISABLED #################

        # clear any existing text colors
        self._color_clear()

        # the parse failed, so there will be invalid text to highlight
        if self._parser_error:
            self._color_invalid()

        # paint any valid tokens
        self._color_tokens()

        ################# UPDATES ENABLED #################
        self._line.setUpdatesEnabled(True)

        # done
        return

    def _accept_composition(self):
        """
        Save the user crafted composition to the director.
        """

        #
        # if there's an existing parse error on the shell, there's nothing we
        # can do but pop a hint for the user and have them try again
        #

        if self._parser_error:
            self._ui_hint_tooltip("Invalid Composition", self._parser_error.error_index)
            return

        #
        # While the user is picking a name for the new composite, we might as well
        # try and compute/cache it asynchronously :-). kick the caching off now.
        #

        self._director.cache_composition(self._last_ast, force=True)

        #
        # the user has entered a valid composition that we have parsed. we
        # want to save this to the director, but first we need a name for the
        # new composition. pop a simple dialog prompting the user for a
        # composition name
        #

        ok, coverage_name = prompt_string(
            "Composition Name:",
            "Please enter a name for this composition",
            "COMP_%s" % self.text
        )

        #
        # once the naming prompt closes, the composing shell tries to pop
        # the coverage hint again which can make it annoying and too
        # aggressive.
        #
        # clearing focus on the text line will ensure the hint does not pop
        #

        self._line.clearFocus()

        #
        # returning back to the naming prompt, if the user did not enter a
        # coverage name (or hit cancel), we will abort saving the composition
        #

        if not (ok and coverage_name):
            return

        #
        # a name was given and all is good, ask the director to save the last
        # composition under the user specified coverage name
        #

        self._director.add_composition(coverage_name, self._last_ast)

        # switch to the newly created composition
        self._director.select_coverage(coverage_name)

    #--------------------------------------------------------------------------
    # Coverage Hint
    #--------------------------------------------------------------------------

    def _ui_hint_coverage_refresh(self):
        """
        Draw the coverage hint as applicable.
        """

        #
        # if the shell is not focused (or empty), don't bother to show a hint
        # as it frequently gets in the way and is really annoying...
        #

        if not (self._line.hasFocus() and self.text):
            self._ui_hint_coverage_hide()
            return

        # scrape info from the current shell text state
        cursor_index = self._line.textCursor().position()
        text_token   = self._get_cursor_coverage_token(cursor_index)

        #
        # if the user's text cursor is touching the index that produced the
        # parse error (assuming there was one) ...
        #

        if self._parser_error and self._parser_error.error_index == cursor_index:

            #
            # if the parse error indicates the parse failed because it expected
            # a coverage token but didn't get one, show the complete coverage
            # list. The user should know their list of options bro.
            #

            if self._parser_error.expected == TokenCoverageSingle:
                self._ui_hint_coverage_show()

        #
        # if the user's text cursor is touching a valid coverage token, we want
        # to pop a hint that shows the details for the coverage matching that
        # explicit token / shorthand. It's a subtle convenience :-)
        #

        elif text_token and (text_token.type == "COVERAGE_TOKEN"):
            self._ui_hint_coverage_show(text_token.value)

        #
        # if the user's text cursor is not touching any text index of interest,
        # there's no reason for us to show any sort of hints. be sure any hints
        # are hidden.
        #

        else:
            self._ui_hint_coverage_hide()

        # done
        return

    def _ui_hint_coverage_show(self, prefix=''):
        """
        Show the coverage hint at the shell's cursor position.

        Optionally, one can specify a prefix (eg, the shorthand 'A') to
        limit the scope of coverage items hinted.
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

        # show the coverage hint popup
        self._completer.complete(cr)
        self._completer.popup().repaint() # reduces hint flicker on the Hot Shell

        # done
        return

    def _ui_hint_coverage_hide(self):
        """
        Hide the coverage hint.
        """
        self._completer.popup().hide()

    def _get_cursor_coverage_token(self, index):
        """
        Get the coverage token touching the cursor (if there is one).
        """

        # iterate through the list of parsed tokens on the line edit / shell
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
    # Composition Highlighting
    #--------------------------------------------------------------------------

    def _color_tokens(self):
        """
        Syntax highlight the valid composition tokens.
        """

        # more code-friendly, readable aliases
        TOKEN_COLORS = self._palette.TOKEN_COLORS

        #
        # in order to syntax highlight text of interest, we must use a text
        # cursor as the vehicle to move around the text box (shell) and
        # manipulate its contents (eg, painting colors)
        #
        # this is simply the way Qt exposes this functionality
        #

        # alias the user cursor, and save its original (current) position
        cursor = self._line.textCursor()
        cursor_position = cursor.position()

        # configure text formatting properties we want our cursor to apply
        highlight = QtGui.QTextCharFormat()
        highlight.setFontWeight(QtGui.QFont.Bold)   # bolds text we 'type'

        #
        # we are about to start painting our text, but we want to disable the
        # shell from emitting any textChanged/cursorMoved kind of signals
        # that originate from our painting code.
        #
        # we use the blockSignals gateways below to disable/enable the signals
        # for the duration of our painting.
        #

        self._line.blockSignals(True)
        ################# UPDATES DISABLED #################

        # iterate through every parsed token, and paint it
        for token in self._parsed_tokens:

            # if the palette doesn't define a color for this token, ignore it
            if token.type not in TOKEN_COLORS:
                continue

            # alias the start and end indexes of the text token to paint
            token_start, token_end = token.span

            # 'click' and 'drag' to select the token text
            cursor.setPosition(token_start, QtGui.QTextCursor.MoveAnchor)
            cursor.setPosition(token_end,   QtGui.QTextCursor.KeepAnchor)

            # configure the colors/style for this explicit token
            #highlight.setBackground(QtGui.QBrush(QtGui.QColor(TOKEN_COLORS[token.type])))
            highlight.setForeground(QtGui.QBrush(TOKEN_COLORS[token.type]))
            cursor.setCharFormat(highlight)

        #
        # we are done painting all the parsed tokens. let's restore the user
        # cursor back to its original state so they are none-the-wiser
        #

        cursor.setPosition(cursor_position)
        cursor.setCharFormat(QtGui.QTextCharFormat())
        self._line.setTextCursor(cursor)

        ################# UPDATES ENABLED #################
        self._line.blockSignals(False)

        # done
        return

    def _color_invalid(self):
        """
        Highlight the invalid (un-parsable) text.

        Please read through the _color_tokens() function for a more
        complete walkthrough of the text painting process.
        """
        assert self._parser_error

        # the invalid text starts from the token that caused a parse error
        invalid_start = self._parser_error.error_index
        invalid_text  = self.text[invalid_start:]

        # no invalid text? nothing to highlight I guess!
        if not invalid_text:
            return

        # alias the user cursor, and save its original (current) position
        cursor = self._line.textCursor()
        cursor_position = cursor.position()

        # setup the invalid text highlighter
        invalid_color = self._palette.invalid_highlight
        highlight = QtGui.QTextCharFormat()
        highlight.setFontWeight(QtGui.QFont.Bold)
        highlight.setBackground(QtGui.QBrush(QtGui.QColor(invalid_color)))

        self._line.blockSignals(True)
        ################# UPDATES DISABLED #################

        # select the invalid text
        cursor.setPosition(invalid_start, QtGui.QTextCursor.MoveAnchor)
        cursor.setPosition(len(self.text), QtGui.QTextCursor.KeepAnchor)

        # insert a highlighted version of the invalid text
        cursor.setCharFormat(highlight)

        # reset the cursor position & style
        cursor.setPosition(cursor_position)
        cursor.setCharFormat(QtGui.QTextCharFormat())
        self._line.setTextCursor(cursor)

        ################# UPDATES ENABLED #################
        self._line.blockSignals(False)

        # done
        return

    #--------------------------------------------------------------------------
    # General Highlighting
    #--------------------------------------------------------------------------

    def _color_clear(self):
        """
        Clear any existing text colors.
        """
        self._color_text()

    def _color_text(self, color=None, start=0, end=0):
        """
        Color shell text with the given color.
        """

        # if no end was specified, apply the style till the end of input
        if end == 0:
            end = len(self.text)

        # alias the user cursor, and save its original (current) position
        cursor = self._line.textCursor()
        cursor_position = cursor.position()

        # setup a simple font coloring (or clearing) text format
        simple = QtGui.QTextCharFormat()
        if color:
            simple.setForeground(QtGui.QBrush(QtGui.QColor(color)))

        self._line.blockSignals(True)
        ################# UPDATES DISABLED #################

        # select the entire line
        cursor.setPosition(start, QtGui.QTextCursor.MoveAnchor)
        cursor.setPosition(end, QtGui.QTextCursor.KeepAnchor)

        # set all the text to the simple format
        cursor.setCharFormat(simple)

        # reset the cursor position & style
        cursor.setPosition(cursor_position)
        self._line.setTextCursor(cursor)

        ################# UPDATES ENABLED #################
        self._line.blockSignals(False)

        # done
        return

#------------------------------------------------------------------------------
# Composing Line
#------------------------------------------------------------------------------

class ComposingLine(QtWidgets.QPlainTextEdit):
    """
    The textbox UI where user compositions are entered (typed).

    While this a QLineEdit may appear to be more appropriate for our
    'Composing Shell', its support for syntax highlighting like features
    are completely absent.

    QPlainTextEdit has much better support for coloring or highlighting
    entered text, so we subclass from it and make a best effort attempt
    to make it appear and act like a QLineEdit 'shell'
    """

    #
    # QLineEdit has a signal called 'returnPressed' which fires when the
    # user hits 'return' or 'enter'. This is a convenient signal, but
    # QPlainTextEdit does *not* have an equivalent.
    #
    # We define and fire this signal ourself for consistency and the same
    # conveniences as the one QLineEdit offers.
    #

    returnPressed = QtCore.pyqtSignal()

    def __init__(self, parent=None):
        super(ComposingLine, self).__init__(parent)
        self.setObjectName(self.__class__.__name__)

        # configure the widget for use
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
        self._font.setPointSizeF(normalize_to_dpi(9))
        self._font_metrics = QtGui.QFontMetricsF(self._font)
        self.setFont(self._font)

        # configure the QPlainTextEdit to appear and act as much like a
        # QLineEdit as possible (a single line text box)
        self.setWordWrapMode(QtGui.QTextOption.NoWrap)
        self.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.setTabChangesFocus(True)
        self.setMaximumBlockCount(1)

        # set the height of the textbox based on some arbitrary math :D
        LINE_PADDING = self.document().documentMargin()*2
        line_height = self._font_metrics.height() + LINE_PADDING + 2
        self.setFixedHeight(line_height)

    #--------------------------------------------------------------------------
    # QPlainTextEdit Overloads
    #--------------------------------------------------------------------------

    def keyPressEvent(self, e):
        """
        Overload of the key press event.
        """

        # trap the return/enter key event
        if e.key() == QtCore.Qt.Key_Return or \
           e.key() == QtCore.Qt.Key_Enter:

            #
            # fire our convenience signal notifying listeners that the user
            # pressed enter. this signal firing indicates the user is
            # probably trying to complete their query / input.
            #

            self.returnPressed.emit()

            #
            # now we must consume the keypress so it doesn't get passed on
            # to any other widgets/handlers/put in the text box
            #

            e.accept()

        # business as usual
        else:
            super(ComposingLine, self).keyPressEvent(e)

    def timerEvent(self, e):
        """
        Stubbed out to prevent the QPlainTextEdit selection autoscroll.
        """
        return
