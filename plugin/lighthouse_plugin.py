from lighthouse.util.log import *
from lighthouse.util.disassembler import disassembler

# start the global logger *once*
if not logging_started():
    logger = start_logging()

#------------------------------------------------------------------------------
# Disassembler Agnonstic Plugin Loader
#------------------------------------------------------------------------------

logger.debug("Resolving platform for plugin...")

if disassembler.NAME == "IDA":
    logger.info("Selecting IDA loader...")
    from lighthouse.ida_loader import *

elif disassembler.NAME == "BINJA":
    logger.info("Selecting Binary Ninja loader...")
    from lighthouse.binja_loader import *

else:
    raise RuntimeError("DISASSEMBLER-SPECIFIC SHIM MISSING")

