import sys
import operator

#------------------------------------------------------------------------------
# Python 2/3 Compatibilty Shims
#------------------------------------------------------------------------------

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

#
# xrange shim
#

from past.builtins import xrange

#
# Queue --> queue shim
#

try:
    import Queue as queue
except:
    import queue

#
# iter* shims by Benjamin Peterson, from https://github.com/benjaminp/six
#

if PY3:

    def iterkeys(d, **kw):
        return iter(d.keys(**kw))

    def itervalues(d, **kw):
        return iter(d.values(**kw))

    def iteritems(d, **kw):
        return iter(d.items(**kw))

    def iterlists(d, **kw):
        return iter(d.lists(**kw))

    viewkeys = operator.methodcaller("keys")

    viewvalues = operator.methodcaller("values")

    viewitems = operator.methodcaller("items")

else:

    def iterkeys(d, **kw):
        return d.iterkeys(**kw)

    def itervalues(d, **kw):
        return d.itervalues(**kw)

    def iteritems(d, **kw):
        return d.iteritems(**kw)

    def iterlists(d, **kw):
        return d.iterlists(**kw)

    viewkeys = operator.methodcaller("viewkeys")

    viewvalues = operator.methodcaller("viewvalues")

    viewitems = operator.methodcaller("viewitems")
