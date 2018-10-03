from .shim import *
from .util import get_dpi_scale

import logging
logger = logging.getLogger("Lighthouse.Qt.WaitBox")

#--------------------------------------------------------------------------
# Qt WaitBox
#--------------------------------------------------------------------------

class WaitBox(QtWidgets.QDialog):
    """
    A Generic Qt WaitBox Dialog.
    """

    def __init__(self, text, title="Please wait...", abort=None):
        super(WaitBox, self).__init__()

        # dialog text & window title
        self._text = text
        self._title = title

        # abort routine (optional)
        self._abort = abort

        # initialize the dialog UI
        self._ui_init()

    def set_text(self, text):
        """
        Change the waitbox text.
        """
        self._text = text
        self._text_label.setText(text)
        qta = QtCore.QCoreApplication.instance()
        qta.processEvents()

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """
        self.setWindowFlags(
            self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint
        )
        self.setWindowFlags(
            self.windowFlags() | QtCore.Qt.MSWindowsFixedSizeDialogHint
        )
        self.setWindowFlags(
            self.windowFlags() & ~QtCore.Qt.WindowCloseButtonHint
        )

        # configure the main widget / form
        self.setSizeGripEnabled(False)
        self.setModal(True)
        self._dpi_scale = get_dpi_scale()*5.0

        # initialize abort button
        self._abort_button = QtWidgets.QPushButton("Cancel")

        # layout the populated UI just before showing it
        self._ui_layout()

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """
        self.setWindowTitle(self._title)
        self._text_label = QtWidgets.QLabel(self._text)
        self._text_label.setAlignment(QtCore.Qt.AlignHCenter)

        # vertical layout (whole widget)
        v_layout = QtWidgets.QVBoxLayout()
        v_layout.setAlignment(QtCore.Qt.AlignCenter)
        v_layout.addWidget(self._text_label)
        if self._abort:
            self._abort_button.clicked.connect(abort)
            v_layout.addWidget(self._abort_button)

        v_layout.setSpacing(self._dpi_scale*3)
        v_layout.setContentsMargins(
            self._dpi_scale*5,
            self._dpi_scale,
            self._dpi_scale*5,
            self._dpi_scale
        )

        # scale widget dimensions based on DPI
        height = self._dpi_scale * 15
        self.setMinimumHeight(height)

        # compute the dialog layout
        self.setLayout(v_layout)
