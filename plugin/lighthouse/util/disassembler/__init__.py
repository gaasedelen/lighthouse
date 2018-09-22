#--------------------------------------------------------------------------
# Disassembler API Selector
#--------------------------------------------------------------------------
#
#    this file will select and load the shimmed disassembler API for the
#    appropriate (current) disassembler platform.
#
#    see api.py for more details regarding this API shim layer
#

disassembler = None

#--------------------------------------------------------------------------
# IDA API Shim
#--------------------------------------------------------------------------

if disassembler == None:
    try:
        from ida_api import IDAAPI, DockableWindow
        disassembler = IDAAPI()
    except ImportError:
        pass

#--------------------------------------------------------------------------
# Binary Ninja API Shim
#--------------------------------------------------------------------------

if disassembler == None:
    try:
        from binja_api import BinjaAPI, DockableWindow
        disassembler = BinjaAPI()
    except ImportError:
        pass

#--------------------------------------------------------------------------
# Unknown Disassembler
#--------------------------------------------------------------------------

if disassembler == None:
    raise NotImplementedError("Unknown or unsupported disassembler!")

