from .painter import DatabasePainter
from lighthouse.util.disassembler import disassembler

if disassembler.NAME == "IDA":
    from .ida_painter import IDAPainter as CoveragePainter
elif disassembler.NAME == "BINJA":
    from .binja_painter import BinjaPainter as CoveragePainter
else:
    raise NotImplementedError("DISASSEMBLER-SPECIFIC SHIM MISSING")
