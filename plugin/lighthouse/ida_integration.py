import os
import logging

import idaapi
from lighthouse.core import Lighthouse
from lighthouse.util.misc import plugin_resource

logger = logging.getLogger("Lighthouse.IDA.Integration")

#------------------------------------------------------------------------------
# Lighthouse IDA Integration
#------------------------------------------------------------------------------

class LighthouseIDA(Lighthouse):
    """
    Lighthouse UI Integration for IDA Pro.
    """

    def __init__(self):

        # menu entry icons
        self._icon_id_xref = idaapi.BADADDR
        self._icon_id_file = idaapi.BADADDR
        self._icon_id_batch = idaapi.BADADDR
        self._icon_id_overview = idaapi.BADADDR

        # IDA ui hooks
        self._ui_hooks = UIHooks(self)

        # run initialization
        super(LighthouseIDA, self).__init__()

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_LOAD_FILE         = "lighthouse:load_file"
    ACTION_LOAD_BATCH        = "lighthouse:load_batch"
    ACTION_COVERAGE_XREF     = "lighthouse:coverage_xref"
    ACTION_COVERAGE_OVERVIEW = "lighthouse:coverage_overview"

    def _install_load_file(self):
        """
        Install the 'File->Load->Code coverage file...' menu entry.
        """

        # create a custom IDA icon
        icon_path = plugin_resource(os.path.join("icons", "load.png"))
        icon_data = open(icon_path, "rb").read()
        self._icon_id_file = idaapi.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self.ACTION_LOAD_FILE,                   # The action name
            "~C~ode coverage file...",               # The action text
            IDACtxEntry(self.interactive_load_file), # The action handler
            None,                                    # Optional: action shortcut
            "Load individual code coverage file(s)", # Optional: tooltip
            self._icon_id_file                       # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register load_file action with IDA")

        # attach the action to the File-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "File/Load file/",      # Relative path of where to add the action
            self.ACTION_LOAD_FILE,  # The action ID (see above)
            idaapi.SETMENU_APP      # We want to append the action after ^
        )
        if not result:
            RuntimeError("Failed action attach load_file")

        logger.info("Installed the 'Code coverage file' menu entry")

    def _install_load_batch(self):
        """
        Install the 'File->Load->Code coverage batch...' menu entry.
        """

        # create a custom IDA icon
        icon_path = plugin_resource(os.path.join("icons", "batch.png"))
        icon_data = open(icon_path, "rb").read()
        self._icon_id_batch = idaapi.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self.ACTION_LOAD_BATCH,                   # The action name
            "~C~ode coverage batch...",               # The action text
            IDACtxEntry(self.interactive_load_batch), # The action handler
            None,                                     # Optional: action shortcut
            "Load and aggregate code coverage files", # Optional: tooltip
            self._icon_id_batch                       # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register load_batch action with IDA")

        # attach the action to the File-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "File/Load file/",      # Relative path of where to add the action
            self.ACTION_LOAD_BATCH, # The action ID (see above)
            idaapi.SETMENU_APP      # We want to append the action after ^
        )
        if not result:
            RuntimeError("Failed action attach load_batch")

        logger.info("Installed the 'Code coverage batch' menu entry")

    def _install_open_coverage_xref(self):
        """
        Install the right click 'Coverage Xref' context menu entry.
        """

        # create a custom IDA icon
        icon_path = plugin_resource(os.path.join("icons", "batch.png"))
        icon_data = open(icon_path, "rb").read()
        self._icon_id_xref = idaapi.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self.ACTION_COVERAGE_XREF,                # The action name
            "Xrefs coverage sets...",                 # The action text
            IDACtxEntry(self._pre_open_coverage_xref),# The action handler
            None,                                     # Optional: action shortcut
            "List coverage sets containing this address", # Optional: tooltip
            self._icon_id_xref                        # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register coverage_xref action with IDA")

        self._ui_hooks.hook()
        logger.info("Installed the 'Code coverage batch' menu entry")

    def _install_open_coverage_overview(self):
        """
        Install the 'View->Open subviews->Coverage Overview' menu entry.
        """

        # create a custom IDA icon
        icon_path = plugin_resource(os.path.join("icons", "overview.png"))
        icon_data = open(icon_path, "rb").read()
        self._icon_id_overview = idaapi.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self.ACTION_COVERAGE_OVERVIEW,            # The action name
            "~C~overage Overview",                    # The action text
            IDACtxEntry(self.open_coverage_overview), # The action handler
            None,                                     # Optional: action shortcut
            "Open database code coverage overview",   # Optional: tooltip
            self._icon_id_overview                    # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register open coverage overview action with IDA")

        # attach the action to the View-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "View/Open subviews/Hex dump", # Relative path of where to add the action
            self.ACTION_COVERAGE_OVERVIEW, # The action ID (see above)
            idaapi.SETMENU_INS             # We want to insert the action before ^
        )
        if not result:
            RuntimeError("Failed action attach to 'View/Open subviews' dropdown")

        logger.info("Installed the 'Coverage Overview' menu entry")

    def _uninstall_load_file(self):
        """
        Remove the 'File->Load file->Code coverage file...' menu entry.
        """

        # remove the entry from the File-> menu
        result = idaapi.detach_action_from_menu(
            "File/Load file/",
            self.ACTION_LOAD_FILE
        )
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self.ACTION_LOAD_FILE)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_file)
        self._icon_id_file = idaapi.BADADDR

        logger.info("Uninstalled the 'Code coverage file' menu entry")

    def _uninstall_load_batch(self):
        """
        Remove the 'File->Load file->Code coverage batch...' menu entry.
        """

        # remove the entry from the File-> menu
        result = idaapi.detach_action_from_menu(
            "File/Load file/",
            self.ACTION_LOAD_BATCH
        )
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self.ACTION_LOAD_BATCH)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_batch)
        self._icon_id_batch = idaapi.BADADDR

        logger.info("Uninstalled the 'Code coverage batch' menu entry")

    def _uninstall_open_coverage_xref(self):
        """
        Remove the right click 'Coverage Xref' context menu entry.
        """
        self._ui_hooks.unhook()

        # unregister the action
        result = idaapi.unregister_action(self.ACTION_COVERAGE_XREF)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_xref)
        self._icon_id_xref = idaapi.BADADDR

        logger.info("Uninstalled the 'Coverage Xref' menu entry")

    def _uninstall_open_coverage_overview(self):
        """
        Remove the 'View->Open subviews->Coverage Overview' menu entry.
        """

        # remove the entry from the View-> menu
        result = idaapi.detach_action_from_menu(
            "View/Open subviews/Hex dump",
            self.ACTION_COVERAGE_OVERVIEW
        )
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self.ACTION_COVERAGE_OVERVIEW)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_overview)
        self._icon_id_overview = idaapi.BADADDR

        logger.info("Uninstalled the 'Coverage Overview' menu entry")

    #--------------------------------------------------------------------------
    # Helpers
    #--------------------------------------------------------------------------

    def _inject_ctx_actions(self, view, popup, view_type):
        """
        Inject context menu entries into IDA's right click menus.

        NOTE: This is only being used for coverage xref at this time, but
        may host additional actions in the future.

        """

        if view_type == idaapi.BWN_DISASMS:

            idaapi.attach_action_to_popup(
                view,
                popup,
                self.ACTION_COVERAGE_XREF,  # The action ID (see above)
                "Xrefs graph from...",      # Relative path of where to add the action
                idaapi.SETMENU_APP          # We want to append the action after ^
            )

    def _pre_open_coverage_xref(self):
        """
        Grab a contextual address before opening the coverage xref dialog.
        """
        self.open_coverage_xref(idaapi.get_screen_ea())

#------------------------------------------------------------------------------
# IDA UI Helpers
#------------------------------------------------------------------------------

class IDACtxEntry(idaapi.action_handler_t):
    """
    A minimal context menu entry class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS

class UIHooks(idaapi.UI_Hooks):
    """
    Hooks for IDA's UI subsystem.

    At the moment, we are only using these to inject into IDA's right click
    context menus (eg, coverage xrefs)
    """

    def __init__(self, integration):
        self.integration = integration
        super(UIHooks, self).__init__()

    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7.0+)
        """
        if self.integration.director.aggregate.instruction_percent:
            self.integration._inject_ctx_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0

