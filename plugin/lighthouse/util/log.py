import os
import sys
import logging

from .disassembler import disassembler

#------------------------------------------------------------------------------
# Log / Print helpers
#------------------------------------------------------------------------------

def lmsg(message):
    """
    Print a message to the disassembler output window, prefixed with [Lighthouse]
    """

    # prefix the message
    prefix_message = "[Lighthouse] %s" % message

    # only print to disassembler if its output window is alive
    if disassembler.is_msg_inited():
        print prefix_message
    else:
        logger.info(message)

def get_log_dir():
    """
    Return the Lighthouse log directory.
    """
    log_directory = os.path.join(
        disassembler.get_disassembler_user_directory(),
        "lighthouse_logs"
    )
    return log_directory

def logging_started():
    """
    Check if logging has been started.
    """
    return 'logger' in globals()

#------------------------------------------------------------------------------
# Logger Proxy
#------------------------------------------------------------------------------

class LoggerProxy(object):
    """
    Fake file-like stream object that redirects writes to a logger instance.
    """
    def __init__(self, logger, stream, log_level=logging.INFO):
        self._logger    = logger
        self._log_level = log_level
        self._stream    = stream

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self._logger.log(self._log_level, line.rstrip())
        self._stream.write(buf)

    def flush(self):
        pass

    def isatty(self):
        pass

#------------------------------------------------------------------------------
# Initialize Logging
#------------------------------------------------------------------------------

MAX_LOGS = 5
def cleanup_log_directory(log_directory):
    """
    Retain only the last 15 logs.
    """
    filetimes = {}

    # build a map of all the files in the directory, and their last modified time
    for log_name in os.listdir(log_directory):
        filepath = os.path.join(log_directory, log_name)
        if os.path.isfile(filepath):
            filetimes[os.path.getmtime(filepath)] = filepath

    # get the filetimes and check if there's enough to warrant cleanup
    times = filetimes.keys()
    if len(times) < MAX_LOGS:
        return

    logger.debug("Cleaning logs directory")

    # discard the newest 15 logs
    times.sort(reverse=True)
    times = times[MAX_LOGS:]

    # loop through the remaining older logs, and delete them
    for log_time in times:
        try:
            os.remove(filetimes[log_time])
        except Exception as e:
            logger.error("Failed to delete log %s" % filetimes[log_time])
            logger.error(e)

def start_logging():
    global logger

    # create the Lighthouse logger
    logger = logging.getLogger("Lighthouse")

    #
    # only enable logging if the LIGHTHOUSE_LOGGING environment variable is
    # present. we simply return a stub logger to sinkhole messages.
    #

    if os.getenv("LIGHTHOUSE_LOGGING") == None:
        logger.disabled = True
        return logger

    # create a directory for lighthouse logs if it does not exist
    log_dir = get_log_dir()
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # construct the full log path
    log_path = os.path.join(log_dir, "lighthouse.%s.log" % os.getpid())

    # config the logger
    logging.basicConfig(
        filename=log_path,
        format='%(asctime)s | %(name)28s | %(levelname)7s: %(message)s',
        datefmt='%m-%d-%Y %H:%M:%S',
        level=logging.DEBUG
    )

    # proxy STDOUT/STDERR to the log files too
    stdout_logger = logging.getLogger('Lighthouse.STDOUT')
    stderr_logger = logging.getLogger('Lighthouse.STDERR')
    sys.stdout = LoggerProxy(stdout_logger, sys.stdout, logging.INFO)
    sys.stderr = LoggerProxy(stderr_logger, sys.stderr, logging.ERROR)

    # limit the number of logs we keep
    cleanup_log_directory(log_dir)

    return logger

#------------------------------------------------------------------------------
# Log Helpers
#------------------------------------------------------------------------------

def log_config_warning(self, logger, section, field):
    logger.warning("Config missing field '%s' in section '%s", field, section)
