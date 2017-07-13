from lighthouse.util import *
from .parser import *

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
        self._font_metrics = QtGui.QFontMetricsF(self._font)
        self.setFont(self._font)

        # configure the QPlainTextEdit to appear and act as much like a
        # QLineEdit as possible (a single line text box)
        self.setWordWrapMode(QtGui.QTextOption.NoWrap)
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.setTabChangesFocus(True)
        self.setMaximumBlockCount(1)

        # set the height of the textbox based on some arbitrary math :D
        LINE_PADDING = self.document().documentMargin()*2
        line_height = self._font_metrics.height() + LINE_PADDING - 2
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
            # fire our convenience signal notifying listerns that the user
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

    def __init__(self, director, model):
        super(ComposingShell, self).__init__()
        self.setObjectName(self.__class__.__name__)
        self._palette = self._director._palette
        self._model = model
        self._director = director

        # the last known user AST
        self._last_ast = None

        # parser related members
        self._parser = CompositionParser()
        self._parser_error = None
        self._parsed_tokens = []

        # local list of valid shorthand coverage symbols
        self._shorthand = []

        # configure the widget for use
        self._ui_init()

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
        self._line_label.setFont(self._font)

        # the text box / shell / ComposingLine
        self._line = ComposingLine()

        # configure the shell background & default text color
        palette = self._line.palette()
        palette.setColor(QtGui.QPalette.Base, self._palette.composer_bg)
        palette.setColor(QtGui.QPalette.Text, self._palette.composer_fg)
        palette.setColor(QtGui.QPalette.WindowText, self._palette.composer_fg)
        self._line.setPalette(palette)

    def _ui_init_completer(self):
        """
        Initialize the coverage hint UI elements.
        """

        # NOTE/COMPAT:
        if using_pyqt5:
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

        #
        # we need to refresh some of our elements and internal state (say,
        # coverage hint stuff) should the director fire events indicating
        # this data may have changed. install callbacks for these events now.
        #

        self._director.coverage_created(self.refresh)
        self._director.coverage_deleted(self.refresh)
        self._director.coverage_modified(self.refresh)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """

        # create a qt layout
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

    @idafast
    def refresh(self):
        """
        Refresh the shell context.
        """
        self._refresh_hint_list()

    def _refresh_hint_list(self):
        """
        Refresh the shell coverage hint contents.
        """

        # get the most recent coverage strings from the director
        detailed_strings = [self._director.get_coverage_string(x) for x in self._director.coverage_names]
        self._completer_model.setStringList(detailed_strings)
        self._shorthand = [x[0] for x in detailed_strings]

        # queue a UI coverage hint if necessary
        self._ui_hint_coverage_refresh()

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_hint_save_error(self):
        """
        Display a non-intrusive save error hint / tooltip.

        I hate popping up dialogs. most of the time it is a very jarring
        and flow-breaking user experience. even worse, we are tying this
        notification to a very impulsive and error-prone event: the user
        hitting enter/return on the shell.

        I don't want my users to have popup induced rage.

        Instead of popping up a ridiculously annoying dialog telling the
        user we can't parse / save their composition (when they hit enter),
        we instead pop a more palettable tooltip on the shell.

        """
        assert self._parser_error

        # hide the coverage hint if it is visible. things can look cluttered
        # down by the shell if we're trying to show both.
        self._ui_hint_coverage_hide()

        # create a cursor and move it to the parse error location on the shell
        cursor_tip = QtGui.QTextCursor(self._line.document())
        cursor_tip.setPosition(self._parser_error.error_index)

        #
        # using our carefully positioned cursor, we can now extract the relative
        # pixel position of the parse error on the shell and map its global
        # (absolute) pixel position on the screen.
        #

        position = self._line.mapToGlobal(self._line.cursorRect(cursor_tip).topLeft())

        # draw the tooltip at the computed parse error position
        x = QtWidgets.QToolTip.showText(position, "Invalid Composition (Parse Error)")

    def _ui_shell_return_pressed(self):
        """
        Return / Enter pressed in the shell.

        The user pressed 'enter' in the shell, this means we want to try
        and save their composition as a new coverage set to the director.
        """

        #
        # if there's an existing parse error on the shell, there's nothing we
        # can do but pop a hint for the user and have them try again
        #

        if self._parser_error:
            self._ui_hint_save_error()
            return

        # there's no text in the shell text box, so there's nothing for us to do
        if len(self._line.toPlainText()) == 0:
            return

        #
        # TODO/UX: disallow save/create if not on the 'New Composition' option?
        #

        assert self._last_ast

        #
        # While the user is picking a name for the new composite, we might as well
        # try and cache it asynchronously :-)
        #

        self._director.cache_composition(self._last_ast, force=True)

        #
        # the user has entered a valid composition that we have parsed. we
        # want to save this to the director, but first we need a name for the
        # new composition.
        #

        # pop a simple dialog prompting the user for a composition name
        coverage_name = idaapi.askstr(
            0,
            str("COMP_%s" % self._line.toPlainText()),
            "Save composition as..."
        )

        # the user did not enter a coverage name or hit cancel - abort the save
        if not coverage_name:
            return

        #
        # all good, ask the director to save the last composition
        # composition under the given coverage name
        #

        self._director.add_composition(coverage_name, self._last_ast)

        # switch to the newly created composition
        self._director.select_coverage(coverage_name)

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

        # a Search, eg '/DnsParse_'
        if self._parse_search(text):
            self._highlight_search()
            return

        # a Jump, eg '0x804010a'
        elif self._parse_jump(text):
            self._highlight_jump()
            return

        # a Composition, eg '(A | B) - C'
        elif self._parse_composition(text):
            self._ui_hint_coverage_refresh()
            self._highlight_composition()
            return

    #--------------------------------------------------------------------------
    # Search
    #--------------------------------------------------------------------------

    def _parse_search(self, text):
        """
        Parse and execute a serch query.

        A search query is used to filter functions listed in the coverage
        overview table based on their name.

        eg: text = '/DnsParse_'
        """

        # not a search query, ignore
        if not text or text[0] != "/":
            return False

        self._model._search_string = self.text[1:]
        self._model.refresh()

        # done
        return True

    def _highlight_search(self):
        """
        Syntax highlight a search query.
        """

        self._line.setUpdatesEnabled(False)
        ################# UPDATES DISABLED #################

        # clear any existing text colors
        self._color_clear()

        print "TODO: highlight_search"

        ################# UPDATES ENABLED #################
        self._line.setUpdatesEnabled(True)

        # done
        return

    #--------------------------------------------------------------------------
    # Jump
    #--------------------------------------------------------------------------

    def _parse_jump(self, text):
        """
        Parse and execute an address jump query.

        A jump query is used to jump to a function in the coverage overview
        table based on their address.

        eg: text = '0x8040100'
        """

        # not a jump query, ignore
        if not text or not (len(text) > 2 and text[:2].lower() == "0x"):
            return False

        print "TODO: parse_jump"

        # done
        return True

    def _highlight_jump(self):
        """
        Syntax highlight a jump query.
        """

        self._line.setUpdatesEnabled(False)
        ################# UPDATES DISABLED #################

        # clear any existing text colors
        self._color_clear()

        print "TODO: highlight_jump"

        ################# UPDATES ENABLED #################
        self._line.setUpdatesEnabled(True)

        # done
        return

    #--------------------------------------------------------------------------
    # Composition
    #--------------------------------------------------------------------------

    def _parse_composition(self, text):
        """
        Parse and execute a composition query.
        """

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

    #--------------------------------------------------------------------------
    # Coverage Hint
    #--------------------------------------------------------------------------

    def _ui_hint_coverage_refresh(self):
        """
        Draw the coverage hint as applicable.
        """

        #
        # if the shell is not focused, don't bother to show a hint as it
        # frequently gets in the way and is really annoying...
        #

        if not self._line.hasFocus():
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
    # Syntax Highlighting
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
            highlight.setForeground(QtGui.QBrush(QtGui.QColor(TOKEN_COLORS[token.type])))
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
        invalid_text  = text[invalid_start:]

        # no invalid text? nothing to highlight I guess!
        if not invalid_text:
            return

        # alias the user cursor, and save its original (current) position
        cursor = self._line.textCursor()
        cursor_position = cursor.position()

        # setup the invalid text highlighter
        invalid_color = self._palette.invalid_text
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

    def _color_clear(self):
        """
        Clear any existing text colors.
        """

        # alias the user cursor, and save its original (current) position
        cursor = self._line.textCursor()
        cursor_position = cursor.position()

        # setup a blank / default text style
        default = QtGui.QTextCharFormat()

        self._line.blockSignals(True)
        ################# UPDATES DISABLED #################

        # select the entire line
        cursor.setPosition(0, QtGui.QTextCursor.MoveAnchor)
        cursor.setPosition(len(self.text), QtGui.QTextCursor.KeepAnchor)

        # set all the text to the default format
        cursor.setCharFormat(default)

        # reset the cursor position & style
        cursor.setPosition(cursor_position)
        self._line.setTextCursor(cursor)

        ################# UPDATES ENABLED #################
        self._line.blockSignals(False)

        # done
        return
