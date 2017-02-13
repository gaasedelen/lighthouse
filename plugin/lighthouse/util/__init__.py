import idaapi
from log import lmsg, logging_started, start_logging
from qtshim import using_pyqt5, QtCore, QtGui, QtWidgets

def get_disas_bg_color():
    """
    Get the background color of the disas text area via pixel... YOLO

    PS: please expose the get_graph_color(...) palette accessor, Ilfak ;_;
    """

    # find a form (eg, IDA view) to steal a pixel from
    for i in xrange(5):
        form = idaapi.find_tform("IDA View-%c" % chr(ord('A') + i))
        if form:
            break
    else:
        raise RuntimeError("Failed to find donor IDA View")

    # lookup the Qt Widget for the given form, and take a picture of it
    if using_pyqt5():
        widget = idaapi.PluginForm.FormToPyQtWidget(form)
        pixmap = widget.grab(QtCore.QRect(0, 0, widget.width(),2))
    else:
        widget = idaapi.PluginForm.FormToPySideWidget(form)
        pixmap = QtGui.QPixmap.grabWidget(widget, QtCore.QRect(0, 0, widget.width(), 2))

    # extract a pixel from the top center like a pleb
    img    = QtGui.QImage(pixmap.toImage())
    color  = QtGui.QColor(img.pixel(img.width()/2,1))
    return color
