import os
import json
import struct
import logging

from lighthouse.util.qt import *
from lighthouse.util.misc import plugin_resource
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.UI.Palette")

#------------------------------------------------------------------------------
# Theme Util
#------------------------------------------------------------------------------

def swap_rgb(i):
    return struct.unpack("<I", struct.pack(">I", i))[0] >> 8

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

def get_theme_dir():
    """
    Return the Lighthouse theme directory.
    """
    #theme_directory = os.path.join(
    #    disassembler.get_disassembler_user_directory(),
    #    "lighthouse_themes"
    #)
    return plugin_resource("themes")

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

        theme_path = os.path.join(get_theme_dir(), "classic.json")
        theme = self.read_theme(theme_path)
        self.apply_theme(theme)

    #--------------------------------------------------------------------------
    # Theme Loading
    #--------------------------------------------------------------------------

    def read_theme(self, filepath):
        """
        Load a Lighthouse theme file from the given filepath
        """
        logging.debug("Opening theme '%s'..." % filepath)

        # attempt to load the theme file contents from disk
        try:
            raw_theme = open(filepath, "r").read()
        except Exception as e:
            logger.debug("Could not open theme from '%s'" % filepath)
            return None

        # convert the theme file contents to a json object/dict
        try:
            theme = json.loads(raw_theme)
        except Exception as e:
            logger.exception("Could not convert thme '%s' to json" % filepath)
            return None

        return theme

    def apply_theme(self, theme):
        """
        Apply a given theme to Lighthouse.
        """
        logging.debug("Applying theme '%s'..." % theme["name"])
        colors = theme["colors"]

        for field_name, color_name in theme["fields"].items():

            # load the color
            color_value = colors[color_name]
            color = QtGui.QColor(*color_value)

            # set theme self.[field_name] = color
            setattr(self, field_name, color)

        # patchup the theme...
        rgb = int(self.coverage_paint.name()[1:], 16)
        self.coverage_paint = swap_rgb(rgb)

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

        test_widget.setAttribute(103) # taken from http://doc.qt.io/qt-5/qt.html

        # render the (invisible) widget
        test_widget.show()

        # now we farm the background color from the qwidget
        bg_color = test_widget.palette().color(QtGui.QPalette.Window)

        # 'hide' & delete the widget
        test_widget.hide()
        test_widget.deleteLater()

        # return 'Dark' or 'Light'
        return test_color_brightness(bg_color)

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

