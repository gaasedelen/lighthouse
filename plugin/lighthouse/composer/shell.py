from lighthouse.util import *
from .parser import ComposingParser

class ComposingShell(QtWidgets.QWidget):
    """
    TODO
    """

    def __init__(self, director):
        super(ComposingShell, self).__init__()
        self.setObjectName(self.__class__.__name__)

        # TODO
        self._director = director
        self._parser = ComposingParser()

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
        self._ui_init_signals()
        self._ui_layout()

    def _ui_init_shell(self):
        """
        Initialize the Composer UI elements.
        """
        self.line_label = QtWidgets.QLabel("Composer")
        self.line_label.setStyleSheet("QLabel { margin: 0 1ex 0 1ex }")
        self.line_label.setFont(self._font)
        self.line = QtWidgets.QLineEdit()
        self.line.setFont(self._font)

    def _ui_init_signals(self):
        """
        Connect UI signals.
        """

        # text changed on the shell
        self.line.textChanged[str].connect(self._ui_text_changed)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """

        # layout the major elements of our window
        layout = QtWidgets.QHBoxLayout()
        layout.setContentsMargins(0,0,0,0)
        layout.addWidget(self.line_label)
        layout.addWidget(self.line)

        # apply the widget layout
        self.setLayout(layout)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_text_changed(self, text):
        """
        TODO
        """

        # attempt a parse against the composition grammar
        try:
            ast = self._parser.parse(text)

        # parse failed, nothing else to do
        except SyntaxError:
            return

        changed = self._director.apply_composition(ast)

        # TODO: remove
        #if changed:
        #    self.parent.refresh()

