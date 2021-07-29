import os 
import sys

#------------------------------------------------------------------------------
# Binary Ninja 'Plugin Manager' Stub
#------------------------------------------------------------------------------
#
#    This file is an alternative loading stub created specifically to
#    support the ability to 'easy' install Lighthouse into Binary Ninja
#    via its 'Plugin Manager' functionality.
#
#    Please disregard this code / subdirectory if performing **manual**
#    installations of Lighthouse in IDA or Binary Ninja.
#

lh_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "plugins")
sys.path.append(lh_path)

from lighthouse.util.log import logging_started, start_logging
from lighthouse.util.disassembler import disassembler

if not logging_started():
    logger = start_logging()

logger.info("Selecting Binary Ninja loader...")
from lighthouse.integration.binja_loader import *
