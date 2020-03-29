import os
import sys
import inspect
import logging
import traceback

from lighthouse.util.python import iteritems
from .coverage_file import CoverageFile
from lighthouse.exceptions import CoverageParsingError

logger = logging.getLogger("Lighthouse.Reader")

MODULES_DIRECTORY = os.path.join(os.path.dirname(os.path.realpath(__file__)), "parsers")

class CoverageReader(object):
    """
    TODO
    """

    def __init__(self):
        self._installed_parsers = {}
        self._import_parsers()

    def open(self, filepath):
        """
        Open and parse a coverage file from disk.

        Returns a CoverageFile on success, or raises CoverageParsingError on failure.
        """
        coverage_file = None
        parse_failures = {}

        # attempt to parse the given coverage file with each available parser
        for name, parser in iteritems(self._installed_parsers):
            logger.debug("Attempting parse with '%s'" % name)

            # attempt to open/parse the coverage file with the given parser
            try:
                coverage_file = parser(filepath)
                break

            # log the exceptions for each parse failure
            except Exception as e:
                parse_failures[name] = traceback.format_exc()
                logger.debug("| Parse FAILED")

        #
        # if *all* the coverage file parsers failed, raise an exception with
        # information for each failure (for debugging)
        #

        if not coverage_file:
            raise CoverageParsingError(filepath, parse_failures)

        # successful parse
        logger.debug("| Parse OKAY")
        return coverage_file

    def _import_parsers(self):
        """
        Scan and import coverage file parsers.
        """
        target_subclass = CoverageFile
        ignored_files = ["__init__.py"]

        # loop through all the files in the parsers folder
        for filename in os.listdir(MODULES_DIRECTORY):

            # ignore specified files, and anything not *.py
            if filename in ignored_files or filename.endswith(".py") == False:
                continue

            # attempt to load a CoverageFile format from the current *.py file
            logger.debug("| Searching file %s" % filename)
            parser_file = filename[:-3]
            parser_class = self._locate_subclass(parser_file, target_subclass)

            if not parser_class:
                logger.warning("| - No object subclassing from %s found in %s..." \
                             % (target_subclass.__name__, parser_file))
                continue

            # instantiate and add the parser to our dict of imported parsers
            logger.debug("| | Found %s" % parser_class.__name__)
            self._installed_parsers[parser_class.__name__] = parser_class
        logger.debug("+- Done dynamically importing parsers")

        # return the number of modules successfully imported
        return self._installed_parsers

    def _locate_subclass(self, module_file, target_subclass):
        """
        Return the first matching target_subclass in module_file.

        This function is used to scan a specific file (module_file)
        in the Lighthouse parsers directory for class definitions that
        subclass from target_subclass.

        We use this to dynmically import, locate, and return objects
        that are utilizing our CoverageFile abstraction.
        """
        module = None
        module_class = None

        # attempt to import the given filepath as a python module
        try:
            module = __import__("lighthouse.reader.parsers." + module_file, globals(), locals(), ['object'])
        except Exception as e:
            logger.exception("| - Parser import failed")
            return None

        #
        # inspect the module for any classes that subclass from target_subclass
        #   eg: target_subclass == CoverageFile
        #

        class_members = inspect.getmembers(module, inspect.isclass)
        for a_class in class_members:

            # does the current class definition we're inspecting subclass
            # from target_subclass? if so, it is a match
            try:
                if a_class[1].__bases__[0] == target_subclass:
                    module_class = a_class[1]
                    break

            # this class does not subclass / etc / not interesting / ignore it
            except IndexError as e:
                pass

        # return discovered parser or None
        return module_class
