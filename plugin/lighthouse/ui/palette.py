import os
import json
import struct
import shutil
import logging
import traceback

# NOTE: Py2/Py3 compat
try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

from lighthouse.util.qt import *
from lighthouse.util.log import lmsg
from lighthouse.util.misc import *
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.UI.Palette")

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
        self._initialized = False
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

        # load a placeholder theme (unhinted) for inital Lighthoue bring-up
        self._load_preferred_theme(True)
        self._initialized = False

    @staticmethod
    def get_plugin_theme_dir():
        """
        Return the Lighthouse plugin theme directory.
        """
        return plugin_resource("themes")

    @staticmethod
    def get_user_theme_dir():
        """
        Return the Lighthouse user theme directory.
        """
        theme_directory = os.path.join(
            disassembler.get_disassembler_user_directory(),
            "lighthouse_themes"
        )
        return theme_directory

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

    def warmup(self):
        """
        Warms up the theming system prior to initial use.
        """
        if self._initialized:
            return

        logger.debug("Warming up theme subsystem...")

        #
        # attempt to load the user's preferred (or hinted) theme. if we are
        # successful, then there's nothing else to do!
        #

        self._refresh_theme_hints()
        if self._load_preferred_theme():
            self._initialized = True
            logger.debug(" - warmup complete, using preferred theme!")
            return

        #
        # failed to load the preferred theme... so delete the 'active'
        # file (if there is one) and warn the user before falling back
        #

        try:
            os.remove(os.path.join(self.get_user_theme_dir(), ".active_theme"))
        except:
            pass

        disassembler.warning(
            "Failed to load Lighthouse user theme!\n\n"
            "Please check the console for more information..."
        )

        #
        # if no theme is loaded, we will attempt to detect & load the in-box
        # themes based on the user's disassembler theme
        #

        loaded = self._load_preferred_theme(fallback=True)
        if not loaded:
            lmsg("Could not load Lighthouse fallback theme!") # this is a bad place to be...
            return

        logger.debug(" - warmup complete, using hint-recommended theme!")
        self._initialized = True

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
        if not filename:
            return

        #
        # ensure the user is only trying to load themes from the user theme
        # directory as it helps ensure some of our intenal loading logic
        #

        file_dir = os.path.abspath(os.path.dirname(filename))
        user_dir = os.path.abspath(self.get_user_theme_dir())
        if file_dir != user_dir:
            text = "Please install your Lighthouse theme into the user theme directory:\n\n" + user_dir
            disassembler.warning(text)
            return

        #
        # remember the last directory we were in (parsed from a selected file)
        # for the next time the user comes to load coverage files
        #

        if filename:
            self._last_directory = os.path.dirname(filename) + os.sep

        # log the captured (selected) filenames from the dialog
        logger.debug("Captured filename from theme file dialog: '%s'" % filename)

        #
        # before applying the selected lighthouse theme, we should ensure that
        # we know if the user is using a light or dark disassembler theme as
        # it may change which colors get used by the lighthouse theme
        #

        self._refresh_theme_hints()

        # if the selected theme fails to load, throw a visible warning
        if not self._load_theme(filename):
            disassembler.warning(
                "Failed to load Lighthouse user theme!\n\n"
                "Please check the console for more information..."
            )
            return

        # since everthing looks like it loaded okay, save this as the preferred theme
        with open(os.path.join(self.get_user_theme_dir(), ".active_theme"), "w") as f:
            f.write(filename)

    def refresh_theme(self):
        """
        Dynamically compute palette color based on IDA theme.

        Depending on if IDA is using a dark or light theme, we *try*
        to select colors that will hopefully keep things most readable.
        """
        self._refresh_theme_hints()
        self._load_preferred_theme()

    #--------------------------------------------------------------------------
    # Theme Internals
    #--------------------------------------------------------------------------

    def _populate_user_theme_dir(self):
        """
        Create the Lighthouse user theme directory and install default themes.
        """

        # create the user theme directory if it does not exist
        user_theme_dir = self.get_user_theme_dir()
        makedirs(user_theme_dir)

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
            plugin_theme_file = os.path.join(self.get_plugin_theme_dir(), theme_name)
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
        logger.debug("Loading required theme fields from disk...")

        # load a known-good theme from the plugin's in-box themes
        filepath = os.path.join(self.get_plugin_theme_dir(), self._default_themes["dark"])
        theme = self._read_theme(filepath)

        #
        # save all the defined fields in this 'good' theme as a ground truth
        # to validate user themes against...
        #

        self._required_fields = theme["fields"].keys()

    def _load_preferred_theme(self, fallback=False):
        """
        Load the user's preferred theme, or the one hinted at by the theme subsystem.
        """
        logger.debug("Loading preferred theme from disk...")
        user_theme_dir = self.get_user_theme_dir()

        # attempt te read the name of the user's active / preferred theme name
        active_filepath = os.path.join(user_theme_dir, ".active_theme")
        try:
            theme_name = open(active_filepath).read().strip()
            logger.debug(" - Got '%s' from .active_theme" % theme_name)
        except (OSError, IOError):
            theme_name = None

        #
        # if the user does not have a preferred theme set yet, we will try to
        # pick one for them based on their disassembler UI.
        #

        if not theme_name:

            #
            # we have two themes hints which roughly correspond to the tone of
            # their disassembly background, and then their general Qt widgets.
            #
            # if both themes seem to align on style (eg the user is using a
            # 'dark' UI), then we will select the appropriate in-box theme
            #

            if self._user_qt_hint == self._user_disassembly_hint:
                theme_name = self._default_themes[self._user_qt_hint]
                logger.debug(" - No preferred theme, hints suggest theme '%s'" % theme_name)

            #
            # the UI hints don't match, so the user is using some ... weird
            # mismatched theming in their disassembler. let's just default to
            # the 'dark' lighthouse theme as it is more robust
            #

            else:
                theme_name = self._default_themes["dark"]

        #
        # should the user themes be in a bad state, we can fallback to the
        # in-box themes. this should only happen if users malform the default
        # themes that have been copied into the user theme directory
        #

        if fallback:
            theme_path = os.path.join(self.get_plugin_theme_dir(), theme_name)
        else:
            theme_path = os.path.join(self.get_user_theme_dir(), theme_name)

        # finally, attempt to load & apply the theme -- return True/False
        return self._load_theme(theme_path)

    def _validate_theme(self, theme):
        """
        Pefrom rudimentary theme validation.
        """
        logger.debug(" - Validating theme fields for '%s'..." % theme["name"])
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
        except JSONDecodeError as e:
            lmsg("Failed to decode theme '%s' to json" % filepath)
            lmsg(" - " + str(e))
            return False

        # do some basic sanity checking on the given theme file
        if not self._validate_theme(theme):
            return False

        # try applying the loaded theme to Lighthouse
        try:
            self._apply_theme(theme)
        except Exception as e:
            lmsg("Failed to load Lighthouse user theme\n%s" % e)
            return False

        # return success
        self._notify_theme_changed()
        return True

    def _read_theme(self, filepath):
        """
        Parse the Lighthouse theme file from the given filepath.
        """
        logger.debug(" - Reading theme file '%s'..." % filepath)

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
        logger.debug(" - Applying theme '%s'..." % theme["name"])
        colors = theme["colors"]

        for field_name, color_entry in theme["fields"].items():

            # color has 'light' and 'dark' variants
            if isinstance(color_entry, list):
                color_name = self._pick_best_color(field_name, color_entry)

            # there is only one color defined
            else:
                color_name = color_entry

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

    def _pick_best_color(self, field_name, color_entry):
        """
        Given a variable color_entry, select the best color based on the theme hints.
        """
        assert len(color_entry) == 2, "Malformed color entry, must be (dark, light)"
        dark, light = color_entry

        # coverage_paint is actually the only field that applies to disas...
        if field_name == "coverage_paint":
            if self._user_disassembly_hint == "dark":
                return dark
            else:
                return light

        # the rest of the fields should be considered 'qt' fields
        if self._user_qt_hint == "dark":
            return dark

        return light

    #--------------------------------------------------------------------------
    # Theme Inference
    #--------------------------------------------------------------------------

    def _refresh_theme_hints(self):
        """
        Peek at the UI context to infer what kind of theme the user might be using.
        """
        self._user_qt_hint = self._qt_theme_hint()
        self._user_disassembly_hint = self._disassembly_theme_hint() or "dark"

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
        if not bg_color:
            logger.debug(" - Failed to get hint for disassembly background...")
            return None

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

        if disassembler.NAME == "BINJA":
            test_widget.setAttribute(QtCore.Qt.WA_DontShowOnScreen)
        else:
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
