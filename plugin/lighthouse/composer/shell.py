from lighthouse.util import *
from .parser import ComposingParser

class ComposingShell(QtWidgets.QLineEdit):
    """
    The Composing Shell, where music is made.
    """

    def __init__(self, parent, director):
        super(ComposingShell, self).__init__()
        self.setObjectName(self.__class__.__name__)
        self.parent = parent

        self.parser = ComposingParser()
        self._director = director

        # initialize UI elements
        self._ui_init()

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """
        self.textChanged[str].connect(self._text_changed)

    def _text_changed(self, data):
        """
        TODO
        """
        data = data.strip()

        try:
            ast = self.parser.parse(data)
        except SyntaxError:
            return

        changed = self._director.apply_composition(ast)
        if changed:
            self.parent.refresh()
