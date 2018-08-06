disassembler = None

# attempt to load IDA imports
if disassembler == None:
    try:
        from ida_api import IDAAPI
        disassembler = IDAAPI()
    except ImportError:
        pass

# attempt to load Binary Ninja imports
if disassembler == None:
    try:
        from binja_api import BinjaAPI
        disassembler = BinjaAPI()
    except ImportError:
        pass

# throw a hard error on unknown disassembly frameworks
if disassembler == None:
    raise RuntimeError("Unknown or unsupported disassembler!")

