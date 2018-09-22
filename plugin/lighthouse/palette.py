
from lighthouse.util.qt import *
from lighthouse.util.disassembler import disassembler

#
# TODO/FUTURE: this file is a huge mess, and will probably be refactored
# whenever I add external theme customization/controls (v0.9?)
#

#------------------------------------------------------------------------------
# Plugin Color Palette
#------------------------------------------------------------------------------

class LighthousePalette(object):
    """
    Color Palette for the Lighthouse plugin.
    """

    def __init__(self):
        """
        Initialize default palette colors for Lighthouse.
        """

        # one-time initialization flag, used for selecting initial palette
        self._initialized = False

        # the active theme name
        self._qt_theme  = "Dark"
        self._disassembly_theme = "Dark"

        # the list of available themes
        self._themes = \
        {
            "Dark":  0,
            "Light": 1,
        }

        #
        # Coverage Overview
        #

        self._selection     = [QtGui.QColor(100, 0, 130),  QtGui.QColor(226, 143, 0)]
        self._coverage_none = [QtGui.QColor(30, 30, 30),   QtGui.QColor(30, 30, 30)]
        self._coverage_bad  = [QtGui.QColor(221, 0, 0),    QtGui.QColor(207, 31, 0)]
        self._coverage_okay = [QtGui.QColor("#bf7ae7"),    QtGui.QColor(207, 31, 0)]
        self._coverage_good = [QtGui.QColor(51, 153, 255), QtGui.QColor(75, 209, 42)]

        #
        # IDA Views / HexRays
        #

        self._coverage_paint = [0x990000, 0xFFE2A8] # NOTE: IDA uses BBGGRR

        #
        # Composing Shell
        #

        self._overview_bg = [QtGui.QColor(20, 20, 20),    QtGui.QColor(20, 20, 20)]
        self._composer_fg = [QtGui.QColor(255, 255, 255), QtGui.QColor(255, 255, 255)]

        self._valid_text        = [0x80F0FF, 0x0000FF]
        self._invalid_text      = [0xF02070, 0xFF0000]
        self._invalid_highlight = [0x990000, 0xFF0000]

        self._shell_hint_bg = [QtGui.QColor(45, 45, 45), QtGui.QColor(45, 45, 45)]
        self._shell_hint_fg = [QtGui.QColor(255, 255, 255), QtGui.QColor(255, 255, 255)]

        self._combobox_bg = [QtGui.QColor(45, 45, 45), QtGui.QColor(45, 45, 45)]
        self._combobox_fg = [QtGui.QColor(255, 255, 255), QtGui.QColor(255, 255, 255)]

        self._combobox_selection_bg = [QtGui.QColor(51, 153, 255), QtGui.QColor(51, 153, 255)]
        self._combobox_selection_fg = [QtGui.QColor(255, 255, 255), QtGui.QColor(255, 255, 255)]

        #
        # Composition Grammar
        #

        self._logic_token    = [QtGui.QColor("#F02070"), QtGui.QColor("#FF0000")]
        self._comma_token    = [QtGui.QColor("#00FF00"), QtGui.QColor("#0000FF")]
        self._paren_token    = [QtGui.QColor("#40FF40"), QtGui.QColor("#0000FF")]
        self._coverage_token = [QtGui.QColor("#80F0FF"), QtGui.QColor("#000000")]

    #--------------------------------------------------------------------------
    # Theme Management
    #--------------------------------------------------------------------------

    @property
    def disassembly_theme(self):
        """
        Return the active IDA theme number.
        """
        return self._themes[self._disassembly_theme]

    @property
    def qt_theme(self):
        """
        Return the active Qt theme number.
        """
        return self._themes[self._qt_theme]

    def refresh_colors(self):
        """
        Dynamically compute palette color based on IDA theme.

        Depending on if IDA is using a dark or light theme, we *try*
        to select colors that will hopefully keep things most readable.
        """

        # TODO/FUTURE: temporary until I have a cleaner way to do one-time init
        if self._initialized:
            return

        #
        # TODO/THEME:
        #
        #   the dark table (Qt) theme is way better than the light theme
        #   right now, so we're just going to force that on for everyone
        #   for the time being.
        #

        self._qt_theme  = "Dark" # self._qt_theme_hint()
        self._disassembly_theme = self._disassembly_theme_hint()

        # mark the palette as initialized
        self._initialized = True

    def _disassembly_theme_hint(self):
        """
        Binary hint of the IDA color theme.

        This routine returns a best effort hint as to what kind of theme is
        in use for the IDA Views (Disas, Hex, HexRays, etc).

        Returns 'Dark' or 'Light' indicating the user's theme
        """

        #
        # determine whether to use a 'dark' or 'light' paint based on the
        # background color of the user's IDA text based windows
        #

        bg_color = disassembler.get_disassembly_background_color()

        # return 'Dark' or 'Light'
        return test_color_brightness(bg_color)

    def _qt_theme_hint(self):
        """
        Binary hint of the Qt color theme.

        This routine returns a best effort hint as to what kind of theme the
        QtWdigets throughout IDA are using. This is to accomodate for users
        who may be using Zyantific's IDASkins plugins (or others) to further
        customize IDA's appearance.

        Returns 'Dark' or 'Light' indicating the user's theme
        """

        #
        # to determine what kind of Qt based theme IDA is using, we create a
        # test widget and check the colors put into the palette the widget
        # inherits from the application (eg, IDA).
        #

        test_widget = QtWidgets.QWidget()

        #
        # in order to 'realize' the palette used to render (draw) the widget,
        # it first must be made visible. since we don't want to be popping
        # random widgets infront of the user, so we set this attribute such
        # that we can silently bake the widget colors.
        #
        # NOTE/COMPAT: WA_DontShowOnScreen
        #
        #   https://www.riverbankcomputing.com/news/pyqt-56
        #
        #   lmao, don't ask me why they forgot about this attribute from 5.0 - 5.6
        #

        if USING_PYQT5:
            test_widget.setAttribute(103) # taken from http://doc.qt.io/qt-5/qt.html
        else:
            test_widget.setAttribute(QtCore.Qt.WA_DontShowOnScreen)

        # render the (invisible) widget
        test_widget.show()

        # now we farm the background color from the qwidget
        bg_color = test_widget.palette().color(QtGui.QPalette.Window)

        # 'hide' & delete the widget
        test_widget.hide()
        test_widget.deleteLater()

        # return 'Dark' or 'Light'
        return test_color_brightness(bg_color)

    #--------------------------------------------------------------------------
    # Coverage Overview
    #--------------------------------------------------------------------------

    @property
    def selection(self):
        return self._selection[self.qt_theme]

    @property
    def coverage_none(self):
        return self._coverage_none[self.qt_theme]

    @property
    def coverage_bad(self):
        return self._coverage_bad[self.qt_theme]

    @property
    def coverage_okay(self):
        return self._coverage_okay[self.qt_theme]

    @property
    def coverage_good(self):
        return self._coverage_good[self.qt_theme]

    #--------------------------------------------------------------------------
    # IDA Views / HexRays
    #--------------------------------------------------------------------------

    @property
    def coverage_paint(self):
        return self._coverage_paint[self.disassembly_theme]

    #--------------------------------------------------------------------------
    # Composing Shell
    #--------------------------------------------------------------------------

    @property
    def overview_bg(self):
        return self._overview_bg[self.qt_theme]

    @property
    def composer_fg(self):
        return self._composer_fg[self.qt_theme]

    @property
    def valid_text(self):
        return self._valid_text[self.qt_theme]

    @property
    def invalid_text(self):
        return self._invalid_text[self.qt_theme]

    @property
    def invalid_highlight(self):
        return self._invalid_highlight[self.qt_theme]

    @property
    def shell_hint_bg(self):
        return self._shell_hint_bg[self.qt_theme]

    @property
    def shell_hint_fg(self):
        return self._shell_hint_fg[self.qt_theme]

    #--------------------------------------------------------------------------
    # Coverage Combobox
    #--------------------------------------------------------------------------

    @property
    def combobox_bg(self):
        return self._combobox_bg[self.qt_theme]

    @property
    def combobox_fg(self):
        return self._combobox_fg[self.qt_theme]

    @property
    def combobox_selection_bg(self):
        return self._combobox_selection_bg[self.qt_theme]

    @property
    def combobox_selection_fg(self):
        return self._combobox_selection_fg[self.qt_theme]

    #--------------------------------------------------------------------------
    # Composition Grammar
    #--------------------------------------------------------------------------

    @property
    def logic_token(self):
        return self._logic_token[self.qt_theme]

    @property
    def comma_token(self):
        return self._comma_token[self.qt_theme]

    @property
    def paren_token(self):
        return self._paren_token[self.qt_theme]

    @property
    def coverage_token(self):
        return self._coverage_token[self.qt_theme]

    @property
    def TOKEN_COLORS(self):
        """
        Return the palette of token colors.
        """

        return \
        {

            # logic operators
            "OR":    self.logic_token,
            "XOR":   self.logic_token,
            "AND":   self.logic_token,
            "MINUS": self.logic_token,

            # misc
            "COMMA":   self.comma_token,
            "LPAREN":  self.paren_token,
            "RPAREN":  self.paren_token,
            #"WS":      self.whitepsace_token,
            #"UNKNOWN": self.unknown_token,

            # coverage
            "COVERAGE_TOKEN": self.coverage_token,
        }

#------------------------------------------------------------------------------
# Palette Util
#------------------------------------------------------------------------------

def to_rgb(color):
    return ((color >> 16 & 0xFF), (color >> 8 & 0xFF), (color & 0xFF))

def test_color_brightness(color):
    """
    Test the brightness of a color.
    """
    if color.lightness() > 255.0/2:
        return "Light"
    else:
        return "Dark"

def compute_color_on_gradiant(percent, color1, color2):
    """
    Compute the color specified by a percent between two colors.

    TODO/PERF: This is silly, heavy, and can be refactored.
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
