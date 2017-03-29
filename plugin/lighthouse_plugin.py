import os

from idaapi import plugin_t

from lighthouse.ui import *
from lighthouse.util import *
from lighthouse.parsers import *
from lighthouse.director import CoverageDirector
from lighthouse.painting import paint_hexrays

# start the global logger *once*
if not logging_started():
    logger = start_logging()

#------------------------------------------------------------------------------
# IDA Plugin
#------------------------------------------------------------------------------

PLUGIN_VERSION = "0.2.0"
AUTHORS        = "Markus Gaasedelen"
DATE           = "2017"

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return Lighthouse()

class Lighthouse(plugin_t):
    """
    The Lighthouse IDA Plugin.
    """

    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_MOD
    comment = "Code Coverage Explorer"
    help = ""
    wanted_name = "Lighthouse"
    wanted_hotkey = ""

    def __init__(self):

        # plugin color palette
        self.palette = LighthousePalette()

        #----------------------------------------------------------------------

        # the database coverage data conglomerate
        self.director = CoverageDirector(self.palette)

        # hexrays hooks
        self._hxe_events = None

        # plugin qt elements
        self._ui_coverage_overview = CoverageOverview(self.director)

        # members for the 'Load Code Coverage' menu entry
        self._icon_id_load     = idaapi.BADADDR
        self._action_name_load = "lighthouse:load_coverage"

        # members for the 'Coverage Overview' menu entry
        self._icon_id_overview     = idaapi.BADADDR
        self._action_name_overview = "lighthouse:coverage_overview"

    #--------------------------------------------------------------------------
    # IDA Plugin Overloads
    #--------------------------------------------------------------------------

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        # attempt plugin initialization
        try:
            self._install_plugin()

        # failed to initialize or integrate the plugin, log and skip loading
        except Exception as e:
            logger.exception("Failed to initialize")
            return idaapi.PLUGIN_SKIP

        # plugin loaded successfully, print the Lighthouse banner
        self.print_banner()
        logger.info("Successfully initialized")

        # tell IDA to keep the plugin loaded (everything is okay)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        idaapi.warning("The Lighthouse plugin cannot be run as a script.")

    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """

        # attempt to cleanup and uninstall our plugin instance
        try:
            self._uninstall_plugin()

        # failed to cleanly remove the plugin, log failure
        except Exception as e:
            logger.exception("Failed to cleanly unload the plugin")

        logger.info("-"*75)
        logger.info("Plugin terminated")

    #--------------------------------------------------------------------------
    # Initialization
    #--------------------------------------------------------------------------

    def _install_plugin(self):
        """
        Initialize & integrate the plugin into IDA.
        """
        self._install_ui()

        # NOTE: let's delay these till coverage load instead
        #self._install_hexrays_hooks()

    def _install_hexrays_hooks(self):
        """
        Install Hexrays hook listeners.
        """

        # event hooks appear to already be installed for hexrays
        if self._hxe_events:
            return

        # ensure hexrays is loaded & ready for use
        if not idaapi.init_hexrays_plugin():
            raise RuntimeError("HexRays not available for hooking")

        #
        # map our callback function to an actual member since we can't properly
        # remove bindings from IDA callback registrations otherwise. it also
        # makes installation tracking/status easier.
        #

        self._hxe_events = self._hexrays_callback

        # install the callback handler
        assert idaapi.install_hexrays_callback(self._hxe_events)

    def print_banner(self):
        """
        Print the Lighthouse plugin banner.
        """

        # build the main banner title
        banner_params = (PLUGIN_VERSION, AUTHORS, DATE)
        banner_title  = "Lighthouse v%s - (c) %s - %s" % banner_params

        # print plugin banner
        lmsg("")
        lmsg("-"*75)
        lmsg("---[ %s" % banner_title)
        lmsg("-"*75)
        lmsg("")

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _install_ui(self):
        """
        Initialize & integrate all UI elements.
        """

        # install the 'Load Coverage' file dialog
        self._install_load_file_dialog()
        self._install_open_coverage_overview()

    def _install_load_file_dialog(self):
        """
        Install the 'File->Load->Code Coverage File(s)...' menu entry.
        """

        # createa a custom IDA icon
        self._icon_id_load = idaapi.load_custom_icon(
            data=str(open(resource_file("icons/load.png"), "rb").read())
        )

        # describe the action
        # add an menu entry to the options dropdown on the IDA toolbar
        action_desc = idaapi.action_desc_t(
            self._action_name_load,                   # The action name.
            "~C~ode Coverage File(s)...",             # The action text.
            IDACtxEntry(self.load_code_coverage),     # The action handler.
            None,                                     # Optional: action shortcut
            "Load a code coverage file for this IDB", # Optional: tooltip
            self._icon_id_load                        # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register load coverage action with IDA")

        # attach the action to the File-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "File/Load file/",       # Relative path of where to add the action
            self._action_name_load,  # The action ID (see above)
            idaapi.SETMENU_APP       # We want to append the action after ^
        )
        if not result:
            RuntimeError("Failed to attach load action to 'File/Load file/' dropdown")

        logger.info("Installed the 'Load Code Coverage' menu entry")

    def _install_open_coverage_overview(self):
        """
        Install the 'View->Open subviews->Coverage Overview' menu entry.
        """

        # createa a custom IDA icon
        self._icon_id_overview = idaapi.load_custom_icon(
            data=str(open(resource_file("icons/overview.png"), "rb").read())
        )

        # describe the action
        # add an menu entry to the options dropdown on the IDA toolbar
        action_desc = idaapi.action_desc_t(
            self._action_name_overview,               # The action name.
            "~C~overage Overview",                    # The action text.
            IDACtxEntry(self.open_coverage_overview), # The action handler.
            None,                                     # Optional: action shortcut
            "Open database code coverage overview",   # Optional: tooltip
            self._icon_id_overview                    # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register open coverage overview action with IDA")

        # attach the action to the File-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "View/Open subviews/Hex dump", # Relative path of where to add the action
            self._action_name_overview,    # The action ID (see above)
            idaapi.SETMENU_INS             # We want to append the action after ^
        )
        if not result:
            RuntimeError("Failed to attach open action to 'subviews' dropdown")

        logger.info("Installed the 'Coverage Overview' menu entry")

    #--------------------------------------------------------------------------
    # Termination
    #--------------------------------------------------------------------------

    def _uninstall_plugin(self):
        """
        Cleanup & uninstall the plugin from IDA.
        """
        self._uninstall_ui()
        self._uninstall_hexrays_hooks()

    def _uninstall_hexrays_hooks(self):
        """
        Cleanup & uninstall Hexrays hook listeners.
        """
        if not self._hxe_events:
            return

        # remove the callbacks
        #    NOTE: w/e IDA removes this anyway.....
        #idaapi.remove_hexrays_callback(self._hxe_events)
        self._hxe_events = None

    #--------------------------------------------------------------------------
    # Termination - UI
    #--------------------------------------------------------------------------

    def _uninstall_ui(self):
        """
        Cleanup & uninstall the plugin UI from IDA.
        """
        self._uninstall_open_coverage_overview()
        self._uninstall_load_file_dialog()

    def _uninstall_load_file_dialog(self):
        """
        Remove the 'File->Load file->Code Coverage File(s)...' menu entry.
        """

        # remove the entry from the File-> menu
        result = idaapi.detach_action_from_menu(
            "File/Load file/",                 # Relative path of where we put the action
            self._action_name_load)
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self._action_name_load)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_load)
        self._icon_id_load = idaapi.BADADDR

        logger.info("Uninstalled the 'Load Code Coverage' menu entry")

    def _uninstall_open_coverage_overview(self):
        """
        Remove the 'View->Open subviews->Coverage Overview' menu entry.
        """

        # remove the entry from the View-> menu
        result = idaapi.detach_action_from_menu(
            "View/Open subviews/Hex dump",    # Relative path of where we put the action
            self._action_name_overview)
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self._action_name_overview)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_overview)
        self._icon_id_overview = idaapi.BADADDR

        logger.info("Uninstalled the 'Coverage Overview' menu entry")

    #--------------------------------------------------------------------------
    # UI - Actions
    #--------------------------------------------------------------------------

    def load_code_coverage(self):
        """
        Interactive file dialog based loading of Code Coverage.
        """

        # prompt the user with a QtFileDialog to select coverage files
        coverage_files = self._select_code_coverage_files()
        if not coverage_files:
            return

        # TODO: move
        self.palette.refresh_colors()

        #
        # I do not hold great confidence in this code yet, so let's wrap
        # this in a try/catch so the user doesn't get stuck with a wait
        # box they can't close should things go poorly
        #

        try:

            #
            # collect underlying database metadata so that the plugin core can
            # process, map, and manipulate coverage data in a performant manner.
            #
            # TODO: do this asynchronously as the user is selecting files
            #

            idaapi.show_wait_box("Building database metadata...")
            self.director.refresh()

            #
            # load the selected code coverage files into the plugin core
            #

            idaapi.replace_wait_box("Loading coverage files from disk...")
            for filename in coverage_files:
                self.load_code_coverage_file(filename)
            idaapi.hide_wait_box()

        # 'something happened :('
        except Exception as e:
            idaapi.hide_wait_box()
            lmsg("Failed to load coverage:")
            lmsg("- %s" % e)
            logger.exception(e)
            return

        # select the 'first' coverage file loaded
        self.director.select_coverage(os.path.basename(coverage_files[0]))

        # install hexrays hooks if available for this arch/install
        try:
            self._install_hexrays_hooks()
        except RuntimeError:
            pass

        # show the coverage overview
        self.open_coverage_overview()

    def open_coverage_overview(self):
        """
        Open the Coverage Overview dialog.
        """
        self._ui_coverage_overview.Show()

    def _select_code_coverage_files(self):
        """
        Open the 'Load Code Coverage' dialog and capture file selections.
        """

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtWidgets.QFileDialog(None, 'Open Code Coverage File(s)')
        file_dialog.setFileMode(QtWidgets.QFileDialog.ExistingFiles)

        # prompt the user with the file dialog, and await filename(s)
        filenames, _ = file_dialog.getOpenFileNames()

        # log the captured (selected) filenames from the dialog
        logger.debug("Captured filenames from file dialog:")
        logger.debug(filenames)

        # return the captured filenames
        return filenames

    #--------------------------------------------------------------------------
    # Misc
    #--------------------------------------------------------------------------

    def load_code_coverage_file(self, filename):
        """
        Load code coverage file by filename.

        NOTE: At this time only binary drcov logs are supported.
        """
        basename = os.path.basename(filename)

        # load coverage data from file
        coverage_data = DrcovData(filename)

        # extract the coverage relevant to this IDB (well, the root binary)
        root_filename   = idaapi.get_root_filename()
        coverage_blocks = coverage_data.filter_by_module(root_filename)

        # index the coverage for use
        base = idaapi.get_imagebase()
        indexed_data = index_coverage(base, coverage_blocks)

        # enlighten the coverage director to this new coverage data
        self.director.add_coverage(basename, base, indexed_data)

    def _hexrays_callback(self, event, *args):
        """
        HexRays callback event handler.
        """

        # decompilation text generation is complete and it is about to be shown
        if event == idaapi.hxe_text_ready:
            vdui = args[0]
            cfunc = vdui.cfunc

            # if there's no coverage data for this function, there's nothing to do
            if not cfunc.entry_ea in self.director.coverage.functions:
                return 0

            # paint the decompilation text for this function
            paint_hexrays(
                cfunc,
                self.director.metadata,
                self.director.coverage,
                self.palette.ida_coverage
            )

        return 0

#------------------------------------------------------------------------------
# IDA Plugin Palette
#------------------------------------------------------------------------------

class LighthousePalette(object):
    """
    Color Palette for the Lighthouse plugin.

    TODO: external customization
    """

    def __init__(self):
        """
        Initialize default palette colors for Lighthouse.
        """

        # the active theme name
        self._qt_theme  = "Light"
        self._ida_theme = "Light"

        # the list of available themes
        self._themes = \
        {
            "Dark":  0,
            "Light": 1,
        }

        #
        # Coverage Overview
        #

        self._coverage_bad  = [QtGui.QColor(221, 0, 0),    QtGui.QColor(207, 31, 0)]
        self._coverage_good = [QtGui.QColor(51, 153, 255), QtGui.QColor(75, 209, 42)]

        # TODO: unused for now
        #self._profiling_cold = QtGui.QColor(0,0,0)
        #self._profiling_hot  = QtGui.QColor(0,0,0)

        #
        # IDA Views / HexRays
        #

        self._ida_coverage = [0x990000, 0xC8E696] # NOTE: IDA uses BBGGRR

        #
        # Composing Shell
        #
                               #  dark   -  light
        self._logic_token    = [0xF02070, 0xFF0000] #TODO: light theme colors
        self._comma_token    = [0x00FF00, 0x0000FF]
        self._paren_token    = [0x40FF40, 0x0000FF]
        self._coverage_token = [0x80F0FF, 0x000000]
        self._invalid_text   = [0x990000, 0xFF0000]

    #--------------------------------------------------------------------------
    # Theme Management
    #--------------------------------------------------------------------------

    @property
    def ida_theme(self):
        """
        Return the active IDA theme number.
        """
        return self._themes[self._ida_theme]

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
        self._qt_theme  = self._qt_theme_hint()
        self._ida_theme = self._ida_theme_hint()

    def _ida_theme_hint(self):
        """
        Binary hint of the IDA color theme.

        This routine returns a best effort hint as to what kind of theme is
        in use for the IDA Views (Disas, Hex, HexRays, etc).

        Returns 'Dark' or 'Light' indicating the user's theme
        """

        #
        # determine whether to use a 'dark' or 'light' paint based on the
        # background color of the user's disassembly view
        #

        bg_color = get_disas_bg_color()

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

        if using_pyqt5():
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
    def coverage_bad(self):
        return self._coverage_bad[self.qt_theme]

    @property
    def coverage_good(self):
        return self._coverage_good[self.qt_theme]

    #--------------------------------------------------------------------------
    # IDA Views / HexRays
    #--------------------------------------------------------------------------

    @property
    def ida_coverage(self):
        return self._ida_coverage[self.ida_theme]

    #--------------------------------------------------------------------------
    # Composing Shell
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
    def invalid_text(self):
        return self._invalid_text[self.qt_theme]

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
