from lighthouse.util.log import logging_started, start_logging
from lighthouse.util.disassembler import disassembler

if not logging_started():
    logger = start_logging()

#------------------------------------------------------------------------------
# Disassembler Agnonstic Plugin Loader
#------------------------------------------------------------------------------

logger.debug("Resolving disassembler platform for plugin...")

if disassembler.headless:
    logger.info("Disassembler '%s' is running headlessly" % disassembler.NAME)
    logger.info(" - Lighthouse is not supported in headless modes (yet!)")

elif disassembler.NAME == "IDA":
    logger.info("Selecting IDA loader...")
    from lighthouse.ida_loader import *

elif disassembler.NAME == "BINJA":
    logger.info("Selecting Binary Ninja loader...")
    from lighthouse.binja_loader import *

else:
    raise NotImplementedError("DISASSEMBLER-SPECIFIC SHIM MISSING")

