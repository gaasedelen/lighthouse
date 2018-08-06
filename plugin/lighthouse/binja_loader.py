from lighthouse.binja_integration import LighthouseBinja

import logging
logger = logging.getLogger("Lighthouse.Loader.Binja")

#------------------------------------------------------------------------------
# Lighthouse Binja Loader
#------------------------------------------------------------------------------

try:
    lighthouse = LighthouseBinja()
    lighthouse.load()
except Exception as e:
    logger.exception(e)
    print e

