import functools

import idaapi

class IDPListener(idaapi.IDP_Hooks):
    """
    Stub listener for IDP events.
    """
    def __init__(self):
        super(IDPListener, self).__init__()

#------------------------------------------------------------------------------
# IDA execute_sync decorators
#------------------------------------------------------------------------------

# from: Will Ballenthin
# http://www.williballenthin.com/blog/2015/09/04/idapython-synchronization-decorator
#

def idafast(f):
    """
    decorator for marking a function as fast / UI event
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
    decorator for marking a function as completely async.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        return idaapi.execute_sync(ff, idaapi.MFF_NOWAIT)
    return wrapper

def idawrite(f):
    """
    decorator for marking a function as modifying the IDB.
    schedules a request to be made in the main IDA loop to avoid IDB corruption.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        return idaapi.execute_sync(ff, idaapi.MFF_WRITE)
    return wrapper

def idaread(f):
    """
    decorator for marking a function as reading from the IDB.
    schedules a request to be made in the main IDA loop to avoid
      inconsistent results.
    MFF_READ constant via: http://www.openrce.org/forums/posts/1827
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        return idaapi.execute_sync(ff, idaapi.MFF_READ)
    return wrapper
