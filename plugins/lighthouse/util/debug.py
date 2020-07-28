import sys
import inspect
import cProfile
import traceback

from .log import lmsg
from .disassembler import disassembler

#------------------------------------------------------------------------------
# Debug
#------------------------------------------------------------------------------
#
#    This file contains random snippets of code that I frequently use while
#    developing and debugging parts of lighthouse. I don't expect any of this
#    code to be active or in use for major releases.
#

#------------------------------------------------------------------------------
# Call Profiling
#------------------------------------------------------------------------------

pr = cProfile.Profile()

def profile(func):
    """
    A simple function profiling decorator.
    """
    def wrap(*args, **kwargs):
        global pr
        pr.enable()
        result = func(*args, **kwargs)
        pr.disable()
        pr.print_stats(sort="tottime")
        return result
    return wrap

#------------------------------------------------------------------------------
# Function Line Profiling
#------------------------------------------------------------------------------

try:
    import pprofile
    def line_profile(func):
        def profiled_func(*args, **kwargs):
            try:
                profiler = pprofile.ThreadProfile()
                with profiler():
                    return func(*args, **kwargs)
            finally:
                caller_file = inspect.getfile(func)
                profiler.annotate(pprofile.EncodeOrReplaceWriter(sys.stdout), [caller_file])
        return profiled_func

except ImportError:
    def line_profile(func):
        def nothing(*args, **kwargs):
            return func(*args, **kwargs)
        return nothing

#------------------------------------------------------------------------------
# Error Logging
#------------------------------------------------------------------------------

def catch_errors(func):
    """
    A simple catch-all decorator to try and log Lighthouse crashes.

    This will be used to wrap high-risk or new code, in an effort to catch
    and fix bugs without leaving the user in a stuck state.
    """

    def wrap(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()

            st = traceback.format_stack()[:-1]
            ex = traceback.format_exception(exc_type, exc_value, exc_traceback)[2:]

            # log full crashing callstack to console
            full_error = st + ex
            full_error = ''.join(full_error).splitlines()

            lmsg("Lighthouse experienced an error... please file an issue on GitHub with this traceback:")
            lmsg("")
            for line in full_error:
                lmsg(line)

            # notify the user that a bug occurred
            disassembler.warning(
                "Something bad happend to Lighthouse :-(\n\n" \
                "Please file an issue on GitHub with the traceback from your disassembler console."
            )

    return wrap

