import time
import Queue
import logging
import functools

import idaapi
from .qtshim import using_ida7api, using_pyqt5, QtCore, QtGui, QtWidgets

logger = logging.getLogger("Lighthouse.Util.IDA")

#------------------------------------------------------------------------------
# HexRays Util
#------------------------------------------------------------------------------

def map_line2citem(decompilation_text):
    """
    Map decompilation line numbers to citems.

    -----------------------------------------------------------------------

    This function allows us to build a relationship between citems in the
    ctree and specific lines in the hexrays decompilation text.

    -----------------------------------------------------------------------

    Output:

        +- line2citem:
        |    a map keyed with line numbers, holding sets of citem indexes
        |
        |      eg: { int(line_number): sets(citem_indexes), ... }
        '

    """
    line2citem = {}

    #
    # it turns out that citem indexes are actually stored inline with the
    # decompilation text output, hidden behind COLOR_ADDR tokens.
    #
    # here we pass each line of raw decompilation text to our crappy lexer,
    # extracting any COLOR_ADDR tokens as citem indexes
    #

    for line_number in xrange(decompilation_text.size()):
        line_text = decompilation_text[line_number].line
        line2citem[line_number] = lex_citem_indexes(line_text)

    return line2citem

def map_line2node(cfunc, metadata, line2citem):
    """
    Map decompilation line numbers to node (basic blocks) addresses.

    -----------------------------------------------------------------------

    This function allows us to build a relationship between graph nodes
    (basic blocks) and specific lines in the hexrays decompilation text.

    -----------------------------------------------------------------------

    Output:

        +- line2node:
        |    a map keyed with line numbers, holding sets of node addresses
        |
        |      eg: { int(line_number): set(nodes), ... }
        '

    """
    line2node = {}
    treeitems = cfunc.treeitems
    function_address = cfunc.entry_ea

    #
    # prior to this function, a line2citem map was built to tell us which
    # citems reside on any given line of text in the decompilation output.
    #
    # now, we walk through this line2citem map one 'line_number' at a time in
    # an effort to resolve the set of graph nodes associated with its citems.
    #

    for line_number, citem_indexes in line2citem.iteritems():
        nodes = set()

        #
        # we are at the level of a single line (line_number). we now consume
        # its set of citems (citem_indexes) and attempt to identify the explict
        # graph nodes they claim to be sourced from (by their reported EA)
        #

        for index in citem_indexes:

            # get the code address of the given citem
            try:
                item = treeitems[index]
                address = item.ea

            # apparently this is a thing on IDA 6.95
            except IndexError as e:
                continue

            # find the graph node (eg, basic block) that generated this citem
            try:
                node = metadata.get_node(address)

            # address not mapped to a node... weird. continue to the next citem
            except ValueError:
                #logger.warning("Failed to map node to basic block")
                continue

            #
            # we made it this far, so we must have found a node that contains
            # this citem. save the computed node_id to the list of of known
            # nodes we have associated with this line of text
            #

            nodes.add(node.address)

        #
        # finally, save the completed list of node ids as identified for this
        # line of decompilation text to the line2node map that we are building
        #

        line2node[line_number] = nodes

    # all done, return the computed map
    return line2node

def lex_citem_indexes(line):
    """
    Lex all ctree item indexes from a given line of text.

    -----------------------------------------------------------------------

    The HexRays decompiler output contains invisible text tokens that can
    be used to attribute spans of text to the ctree items that produced them.

    This function will simply scrape and return a list of all the these
    tokens (COLOR_ADDR) which contain item indexes into the ctree.

    """
    i = 0
    indexes = []
    line_length = len(line)

    # lex COLOR_ADDR tokens from the line of text
    while i < line_length:

        # does this character mark the start of a new COLOR_* token?
        if line[i] == idaapi.COLOR_ON:

            # yes, so move past the COLOR_ON byte
            i += 1

            # is this sequence for a COLOR_ADDR?
            if ord(line[i]) == idaapi.COLOR_ADDR:

                # yes, so move past the COLOR_ADDR byte
                i += 1

                #
                # A COLOR_ADDR token is followed by either 8, or 16 characters
                # (a hex encoded number) that represents an address/pointer.
                # in this context, it is actually the index number of a citem
                #

                citem_index = int(line[i:i+idaapi.COLOR_ADDR_SIZE], 16)
                i += idaapi.COLOR_ADDR_SIZE

                # save the extracted citem index
                indexes.append(citem_index)

                # skip to the next iteration as i has moved
                continue

        # nothing we care about happened, keep lexing forward
        i += 1

    # return all the citem indexes extracted from this line of text
    return indexes

#------------------------------------------------------------------------------
# Misc
#------------------------------------------------------------------------------

def get_disas_bg_color():
    """
    Get the background color of an IDA disassembly view.

    -----------------------------------------------------------------------

    The necessity of this function is pretty silly. I would like lighthouse
    to be color-aware of the user's IDA theme such that it selects reasonable
    colors that maintain readability.

    Since there is no supported way to probe the palette & colors in use by
    IDA, we must get creative. This function attempts to locate an IDA
    disassembly view, and take a screenshot of said widget. It will then
    attempt to extract the color of a single background pixel (hopefully).

    PS: please expose the get_graph_color(...) palette accessor, Ilfak ;_;
    """
    if using_ida7api:
        return get_disas_bg_color_ida7()
    else:
        return get_disas_bg_color_ida6()

def get_disas_bg_color_ida7():
    """
    Get the background color of an IDA disassembly view. (IDA 7+)
    """
    import sip

    # find a widget (eg, IDA view) to steal a pixel from
    for i in xrange(5):
        twidget = idaapi.find_widget("IDA View-%c" % chr(ord('A') + i))
        if twidget:
            break
    else:
        raise RuntimeError("Failed to find donor IDA View")

    # take 2px tall screenshot of the widget
    widget = sip.wrapinstance(long(twidget), QtWidgets.QWidget) # NOTE: LOL
    pixmap = widget.grab(QtCore.QRect(0, 0, widget.width(), 2))

    # extract 1 pixel like a pleb (hopefully a background pixel :|)
    img   = QtGui.QImage(pixmap.toImage())
    color = QtGui.QColor(img.pixel(img.width()/2,1))

    # return the color of the pixel we extracted
    return color

def get_disas_bg_color_ida6():
    """
    Get the background color of an IDA disassembly view. (IDA 6.x)
    """

    # find a form (eg, IDA view) to steal a pixel from
    for i in xrange(5):
        form = idaapi.find_tform("IDA View-%c" % chr(ord('A') + i))
        if form:
            break
    else:
        raise RuntimeError("Failed to find donor IDA View")

    # locate the Qt Widget for an IDA View form and take 2px tall screenshot
    if using_pyqt5():
        widget = idaapi.PluginForm.FormToPyQtWidget(form)
        pixmap = widget.grab(QtCore.QRect(0, 0, widget.width(), 2))
    else:
        widget = idaapi.PluginForm.FormToPySideWidget(form)
        region = QtCore.QRect(0, 0, widget.width(), 2)
        pixmap = QtGui.QPixmap.grabWidget(widget, region)

    # extract 1 pixel like a pleb (hopefully a background pixel :|)
    img   = QtGui.QImage(pixmap.toImage())
    color = QtGui.QColor(img.pixel(img.width()/2,1))

    # return the color of the pixel we extracted
    return color

#------------------------------------------------------------------------------
# IDA execute_sync decorators
#------------------------------------------------------------------------------
# from: Will Ballenthin
# http://www.williballenthin.com/blog/2015/09/04/idapython-synchronization-decorator
#

def idafast(f):
    """
    Decorator for marking a function as fast / UI event
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        if idaapi.is_main_thread():
            return ff()
        else:
            return idaapi.execute_sync(ff, idaapi.MFF_FAST)
    return wrapper

def idanowait(f):
    """
    Decorator for marking a function as completely async.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        return idaapi.execute_sync(ff, idaapi.MFF_NOWAIT)
    return wrapper

def idawrite(f):
    """
    Decorator for marking a function as modifying the IDB.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        return idaapi.execute_sync(ff, idaapi.MFF_WRITE)
    return wrapper

def idaread(f):
    """
    Decorator for marking a function as reading from the IDB.

    MFF_READ constant via: http://www.openrce.org/forums/posts/1827
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        return idaapi.execute_sync(ff, idaapi.MFF_READ)
    return wrapper

def mainthread(f):
    """
    A debug decorator to assert main thread execution.
    """
    def wrapper(*args, **kwargs):
        assert idaapi.is_main_thread()
        return f(*args, **kwargs)
    return wrapper

def execute_sync(sync_flags=idaapi.MFF_FAST):
    """
    Synchronization decorator capable of providing return values.

    From https://github.com/vrtadmin/FIRST-plugin-ida
    """
    def real_decorator(function):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            output = [None]

            #
            # this inline function definition is technically what will execute
            # in the context of the main thread. we use this thunk to capture
            # any output the function may want to return to the user.
            #

            def thunk():
                output[0] = function(*args, **kwargs)
                return 1

            # send the synchronization request to IDA
            idaapi.execute_sync(thunk, sync_flags)

            # return the output of the synchronized function
            return output[0]
        return wrapper
    return real_decorator

#------------------------------------------------------------------------------
# IDA Async Magic
#------------------------------------------------------------------------------

@mainthread
def await_future(future, block=True, timeout=1.0):
    """
    This is effectively a technique I use to get around completely blocking
    IDA's mainthread while waiting for a threaded result that may need to make
    use of the sync operators.

    Waiting for a 'future' thread result to come through via this function
    lets other execute_sync actions to slip through (at least Read, Fast).
    """

    elapsed  = 0       # total time elapsed processing this future object
    interval = 0.02    # the interval which we wait for a response
    end_time = time.time() + timeout

    # run until the the future completes or the timeout elapses
    while block or (time.time() < end_time):

        # block for a brief period to see if the future completes
        try:
            return future.get(timeout=interval)

        #
        # the future timed out, so perhaps it is blocked on a request
        # to the mainthread. flush the requests now and try again
        #

        except Queue.Empty as e:
            logger.debug("Flushing execute_sync requests")
            flush_ida_sync_requests()

@mainthread
def flush_ida_sync_requests():
    """
    Flush all execute_sync requests.

    NOTE: This MUST be called from the IDA Mainthread to be effective.
    """
    if not idaapi.is_main_thread():
        return False

    # this will trigger/flush the IDA UI loop
    qta = QtCore.QCoreApplication.instance()
    qta.processEvents()

    # done
    return True
