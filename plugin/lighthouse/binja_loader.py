import logging

from lighthouse.util.log import lmsg
from lighthouse.binja_integration import LighthouseBinja

logger = logging.getLogger("Lighthouse.Binja.Loader")

#------------------------------------------------------------------------------
# Lighthouse Binja Loader
#------------------------------------------------------------------------------
#
#    The Binary Ninja plugin loading process is less involved compared to IDA.
#
#    When Binary Ninja is starting up, it will import all python files placed
#    in its root plugin folder. It will then attempt to import any *directory*
#    in the plugin folder as a python module.
#
#    For this reason, you may see Binary Ninja attempting to load 'lighthouse'
#    and 'lighthouse_plugin' in your console. This is normal due to the way
#    we have structured Lighthouse and its loading process.
#
#    In practice, lighthouse_plugin.py will import the contents of this file,
#    when Binary Ninja is starting up. As such, this is our only opportunity
#    to load & integrate Lighthouse.
#
#    TODO/V35: it would be nice load/unload plugins with BNDB's like IDA
#

try:
    lighthouse = LighthouseBinja()
    lighthouse.load()
except Exception as e:
    lmsg("Failed to initialize Lighthouse")
    logger.exception("Exception details:")

