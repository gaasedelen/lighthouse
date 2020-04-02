import os
import json
import struct
import shutil
import logging
import traceback

from lighthouse.util.qt import *
from lighthouse.util.log import lmsg
from lighthouse.util.disassembler import disassembler
from lighthouse.util.misc import plugin_resource, register_callback, notify_callback

logger = logging.getLogger("Lighthouse.UI.Palette")

#------------------------------------------------------------------------------
# Theme Util
#------------------------------------------------------------------------------

def swap_rgb(i):
    """
    Swap RRGGBB (integer) to BBGGRR.
    """
    return struct.unpack("<I", struct.pack(">I", i))[0] >> 8

def to_rgb(color):
    """
    Split RRGGBB (integer) to (RR, GG, BB) tuple.
    """
    return ((color >> 16 & 0xFF), (color >> 8 & 0xFF), (color & 0xFF))

def test_color_brightness(color):
    """
    Test the brightness of a color.
    """
    if color.lightness() > 255.0/2:
        return "light"
    else:
        return "dark"

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

def get_plugin_theme_dir():
    """
    Return the Lighthouse plugin theme directory.
    """
    return plugin_resource("themes")

def get_user_theme_dir():
    """
    Return the Lighthouse user theme directory.
    """
    theme_directory = os.path.join(
        disassembler.get_disassembler_user_directory(),
        "lighthouse_themes"
    )
    return theme_directory

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
        self._last_directory = None
        self._required_fields = []

        # hints about the user theme (light/dark)
        self._user_qt_hint = "dark"
        self._user_disassembly_hint = "dark"

        self.theme = None
        self._default_themes = \
        {
            "dark":  "synth.json",
            "light": "dullien.json"
        }

        # list of objects requesting a callback after a theme change
        self._theme_changed_callbacks = []

        # get a list of required theme fields, for user theme validation
        self._load_required_fields()

        # initialize the user theme directory
        self._populate_user_theme_dir()

    #----------------------------------------------------------------------
    # Properties
    #----------------------------------------------------------------------

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

    #----------------------------------------------------------------------
    # Callbacks
    #----------------------------------------------------------------------

    def theme_changed(self, callback):
        """
        Subscribe a callback for theme change events.
        """
        register_callback(self._theme_changed_callbacks, callback)

    def _notify_theme_changed(self):
        """
        Notify listeners of a theme change event.
        """
        notify_callback(self._theme_changed_callbacks)

    #----------------------------------------------------------------------
    # Public
    #----------------------------------------------------------------------

    def interactive_change_theme(self):
        """
        Open a file dialog and let the user select a new Lighthoue theme.
        """

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtWidgets.QFileDialog(
            None,
            "Open Lighthouse theme file",
            self._last_directory,
            "JSON Files (*.json)"
        )
        file_dialog.setFileMode(QtWidgets.QFileDialog.ExistingFile)

        # prompt the user with the file dialog, and await filename(s)
        filename, _ = file_dialog.getOpenFileName()

        #
        # ensure the user is only trying to load themes from the user theme
        # directory as it helps ensure some of our intenal loading logic
        #

        file_dir = os.path.abspath(os.path.dirname(filename))
        user_dir = os.path.abspath(get_user_theme_dir())
        if file_dir != user_dir:
            text = "Please install your Lighthouse theme into the user theme directory:\n\n" + user_dir
            disassembler.warning(text)
            lmsg(text)
            return

        #
        # remember the last directory we were in (parsed from a selected file)
        # for the next time the user comes to load coverage files
        #

        if filename:
            self._last_directory = os.path.dirname(filename) + os.sep

        # log the captured (selected) filenames from the dialog
        logger.debug("Captured filename from theme file dialog: '%s'" % filename)

        # load & apply theme from disk
        if self._load_theme(filename):
            return

        # if the selected theme failed to load, throw a visible warning
        disassembler.warning(
            "Failed to load Lighthouse user theme!\n\n"
            "Please check the console for more information..."
        )

    def refresh_theme(self):
        """
        Dynamically compute palette color based on IDA theme.

        Depending on if IDA is using a dark or light theme, we *try*
        to select colors that will hopefully keep things most readable.
        """

        #
        # attempt to load the user's preferred (or hinted) theme. if we are
        # successful, then there's nothing else to do!
        #

        if self._load_preferred_theme():
            return

        #
        # failed to load the preferred theme... so delete the 'active'
        # file (if there is one) and warn the user before falling back
        #

        os.remove(os.path.join(get_user_theme_dir(), ".active_theme"))
        disassembler.warning(
            "Failed to load Lighthouse user theme!\n\n"
            "Please check the console for more information..."
        )

        # if there is already a theme loaded, continue to use it...
        if self.theme:
            return

        #
        # if no theme is loaded, we will attempt to detect & load the in-box
        # themes based on the user's disassembler theme
        #

        loaded = self._load_preferred_theme(fallback=True)
        if loaded:
            return

        lmsg("Could not load Lighthouse fallback theme!")

    #--------------------------------------------------------------------------
    # Theme Internals
    #--------------------------------------------------------------------------

    def _populate_user_theme_dir(self):
        """
        Create the Lighthouse user theme directory and install default themes.
        """

        # create the user theme directory if it does not exist
        user_theme_dir = get_user_theme_dir()
        if not os.path.exists(user_theme_dir):
            os.makedirs(user_theme_dir)

        # copy the default themes into the user directory if they don't exist
        for theme_name in self._default_themes.values():

            #
            # check if lighthouse has copied the default themes into the user
            # theme directory before. when 'default' themes exists, skip them
            # rather than overwriting... as the user may have modified it
            #

            user_theme_file = os.path.join(user_theme_dir, theme_name)
            if os.path.exists(user_theme_file):
                continue

            # copy the in-box themes to the user theme directory
            plugin_theme_file = os.path.join(get_plugin_theme_dir(), theme_name)
            shutil.copy(plugin_theme_file, user_theme_file)

        #
        # if the user tries to switch themes, ensure the file dialog will start
        # in their user theme directory
        #

        self._last_directory = user_theme_dir

    def _load_required_fields(self):
        """
        Load the required theme fields from a donor in-box theme.
        """

        # load a known-good theme from the plugin's in-box themes
        filepath = os.path.join(get_plugin_theme_dir(), self._default_themes["dark"])
        theme = self._read_theme(filepath)

        #
        # save all the defined fields in this 'good' theme as a ground truth
        # to validate user themes against...
        #

        self._required_fields = theme["fields"].keys()

    def _select_preferred_theme(self):
        """
        Return the name of the preferred theme to try loading.
        """
        user_theme_dir = get_user_theme_dir()

        # attempt te read the name of the user's active / preferred theme
        active_filepath = os.path.join(user_theme_dir, ".active_theme")
        try:
            theme_name = open(active_filepath).read().strip()
        except OSError:
            theme_name = None

        #
        # there is no preferred theme set, let's try to peek at the user's
        # disassembler theme & active Qt context and figure out what theme
        # might work best for them (a light theme or dark one, basically)
        #

        if not theme_name:
            self._user_qt_hint = self._qt_theme_hint()
            self._user_disassembly_hint = self._disassembly_theme_hint()

            # if both hints agree with each other, let's shoot for that theme
            if self._user_qt_hint == self._user_disassembly_hint:
                theme_name = self._default_themes[self._user_qt_hint]

            #
            # the UI hints don't match, so the user is using some ... weird
            # colors. let's just default to the 'dark' lighthouse theme as
            # it is more robust and can look okay in both light and dark envs
            #

            else:
                theme_name = self._default_themes["dark"]

        # at this point, a theme_name to load should be known
        return theme_name

    def _load_preferred_theme(self, fallback=False):
        """
        Load the user's preferred theme, or the one hinted at by the theme subsystem.
        """
        theme_name = self._select_preferred_theme()
        if fallback:
            theme_path = os.path.join(get_plugin_theme_dir(), theme_name)
        else:
            theme_path = os.path.join(get_user_theme_dir(), theme_name)
        return self._load_theme(theme_path)

    def _validate_theme(self, theme):
        """
        Pefrom rudimentary theme validation.
        """
        user_fields = theme.get("fields", None)
        if not user_fields:
            lmsg("Could not find theme 'fields' definition")
            return False

        # check that all the 'required' fields exist in the given theme
        for field in self._required_fields:
            if field not in user_fields:
                lmsg("Could not find required theme field '%s'" % field)
                return False

        # theme looks good enough for now...
        return True

    def _load_theme(self, filepath):
        """
        Load and apply the Lighthouse theme at the given filepath.
        """

        # attempt to read json theme from disk
        try:
            theme = self._read_theme(filepath)

        # reading file from dsik failed
        except OSError:
            lmsg("Could not open theme file at '%s'" % filepath)
            return False

        # JSON decoding failed
        except json.decoder.JSONDecodeError as e:
            lmsg("Failed to decode theme '%s' to json" % filepath)
            lmsg(" - " + str(e))
            return False

        # if the theme appears identical to the applied theme. nothing to do!
        if theme == self.theme:
            return True

        # do some basic sanity checking on the given theme file
        if not self._validate_theme(theme):
            return False

        # try applying the loaded theme to Lighthouse
        try:
            self._apply_theme(theme)
        except Exception as e:
            lmsg("Failed to load Lighthouse user theme\n%s" % e)
            return False

        # since everthing looks like it loaded okay, save this as the preferred theme
        with open(os.path.join(get_user_theme_dir(), ".active_theme"), "w") as f:
            f.write(filepath)

        # return success
        self._notify_theme_changed()
        return True

    def _read_theme(self, filepath):
        """
        Parse the Lighthouse theme file from the given filepath.
        """
        logging.debug("Opening theme '%s'..." % filepath)

        # attempt to load the theme file contents from disk
        raw_theme = open(filepath, "r").read()

        # convert the theme file contents to a json object/dict
        theme = json.loads(raw_theme)

        # all good
        return theme

    def _apply_theme(self, theme):
        """
        Apply the given theme definition to Lighthouse.
        """
        logging.debug("Applying theme '%s'..." % theme["name"])
        colors = theme["colors"]

        for field_name, color_name in theme["fields"].items():

            # load the color
            color_value = colors[color_name]
            color = QtGui.QColor(*color_value)

            # set theme self.[field_name] = color
            setattr(self, field_name, color)

        # HACK: IDA uses BBGGRR for its databasse highlighting
        if disassembler.NAME == "IDA":
            rgb = int(self.coverage_paint.name()[1:], 16)
            self.coverage_paint = swap_rgb(rgb)

        # all done, save the theme in case we need it later
        self.theme = theme

    #--------------------------------------------------------------------------
    # Theme Inference
    #--------------------------------------------------------------------------

    def _disassembly_theme_hint(self):
        """
        Binary hint of the IDA color theme.

        This routine returns a best effort hint as to what kind of theme is
        in use for the IDA Views (Disas, Hex, HexRays, etc).

        Returns 'dark' or 'light' indicating the user's theme
        """

        #
        # determine whether to use a 'dark' or 'light' paint based on the
        # background color of the user's IDA text based windows
        #

        bg_color = disassembler.get_disassembly_background_color()

        # return 'dark' or 'light'
        return test_color_brightness(bg_color)

    def _qt_theme_hint(self):
        """
        Binary hint of the Qt color theme.

        This routine returns a best effort hint as to what kind of theme the
        QtWdigets throughout IDA are using. This is to accomodate for users
        who may be using Zyantific's IDASkins plugins (or others) to further
        customize IDA's appearance.

        Returns 'dark' or 'light' indicating the user's theme
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

        # return 'dark' or 'light'
        return test_color_brightness(bg_color)
