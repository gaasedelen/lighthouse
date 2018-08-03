from .painter import DatabasePainter
from lighthouse.util.disassembler import active_disassembler, platform

if active_disassembler == platform.IDA:
    from .ida_painter import IDAPainter as CoveragePainter
elif active_disassembler == platform.BINJA:
    from .binja_painter import BinjaPainter as CoveragePainter
else:
    raise RuntimeError("DISASSEMBLER-SPECIFIC SHIM MISSING")
