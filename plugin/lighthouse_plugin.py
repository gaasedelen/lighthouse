from lighthouse.util.log import *
from lighthouse.util.disassembler import active_disassembler, platform

# start the global logger *once*
if not logging_started():
    logger = start_logging()

#------------------------------------------------------------------------------
# Disassembler Agnonstic Plugin Loader
#------------------------------------------------------------------------------

logger.debug("Resolving platform for plugin...")
if active_disassembler == platform.IDA:
    logger.info("Selecting IDA loader...")
    from lighthouse.ida_loader import *

elif active_disassembler == platform.BINJA:
    logger.info("Selecting Binary Ninja loader...")
    from lighthouse.binja_loader import *
