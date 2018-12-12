#!/usr/bin/python

import os
import sys
import mmap
import struct
import re
from ctypes import *

#------------------------------------------------------------------------------
# drcov log parser
#------------------------------------------------------------------------------

class DrcovData(object):
    """
    A drcov log parser.
    """
    def __init__(self, filepath=None):

        # original filepath
        self.filepath = filepath

        # drcov header attributes
        self.version = 0
        self.flavor  = None

        # drcov module table
        self.module_table_count   = 0
        self.module_table_version = 0
        self.modules = []

        # drcov basic block data
        self.bb_table_count     = 0
        self.bb_table_is_binary = True
        self.basic_blocks = []

        # parse the given filepath
        self._parse_drcov_file(filepath)

    #--------------------------------------------------------------------------
    # Public
    #--------------------------------------------------------------------------

    def get_module(self, module_name, fuzzy=True):
        """
        Get a module by its name.

        Note that this is a 'fuzzy' lookup by default.
        """

        # fuzzy module name lookup
        if fuzzy:

            # attempt lookup using case-insensitive filename
            for module in self.modules:
                if module_name.lower() in module.filename.lower():
                    return module

            #
            # no hits yet... let's cleave the extension from the given module
            # name (if present) and try again
            #

            if "." in module_name:
                module_name = module_name.split(".")[0]

            # attempt lookup using case-insensitive filename without extension
            for module in self.modules:
                if module_name.lower() in module.filename.lower():
                    return module

        # strict lookup
        else:
            for module in self.modules:
                if module_name == module.filename:
                    return module

        # no matching module exists
        return None

    def get_blocks_by_module(self, module_name):
        """
        Extract coverage blocks pertaining to the named module.
        """

        # locate the coverage that matches the given module_name
        module = self.get_module(module_name)

        # if we fail to find a module that matches the given name, bail
        if not module:
            raise ValueError("No coverage for module '%s' in log" % module_name)

        # extract module id for speed
        mod_id = module.id

        # loop through the coverage data and filter out data for only this module
        coverage_blocks = [(bb.start, bb.size) for bb in self.basic_blocks if bb.mod_id == mod_id]

        # return the filtered coverage blocks
        return coverage_blocks

    #--------------------------------------------------------------------------
    # Parsing Routines - Top Level
    #--------------------------------------------------------------------------

    def _parse_drcov_file(self, filepath):
        """
        Parse drcov coverage from the given log file.
        """
        with open(filepath, "rb") as f:
            self._parse_drcov_header(f)
            self._parse_module_table(f)
            self._parse_bb_table(f)

    def _parse_drcov_data(self, drcov_data):
        """
        Parse drcov coverage from the given data blob.
        """
        pass # TODO/DRCOV

    #--------------------------------------------------------------------------
    # Parsing Routines - Internals
    #--------------------------------------------------------------------------

    def _parse_drcov_header(self, f):
        """
        Parse drcov log header from filestream.
        """

        # parse drcov version from log
        #   eg: DRCOV VERSION: 2
        version_line = f.readline().strip()
        self.version = int(version_line.split(":")[1])

        # parse drcov flavor from log
        #   eg: DRCOV FLAVOR: drcov
        flavor_line = f.readline().strip()
        self.flavor = flavor_line.split(":")[1]

        assert self.version == 2, "Only drcov version 2 log files supported"

    def _parse_module_table(self, f):
        """
        Parse drcov log module table from filestream.
        """
        self._parse_module_table_header(f)
        self._parse_module_table_columns(f)
        self._parse_module_table_modules(f)

    def _parse_module_table_header(self, f):
        """
        Parse drcov log module table header from filestream.

        -------------------------------------------------------------------

        Format used in DynamoRIO v6.1.1 through 6.2.0
           eg: 'Module Table: 11'

        Format used in DynamoRIO v7.0.0-RC1 (and hopefully above)
           eg: 'Module Table: version X, count 11'

        """

        # parse module table 'header'
        #   eg: Module Table: version 2, count 11
        header_line = f.readline().strip()
        field_name, field_data = header_line.split(": ")
        #assert field_name == "Module Table"

        #
        # NOTE/COMPAT:
        #
        #   DynamoRIO doesn't document their drcov log format, and it has
        #   changed its format at least once during its lifetime.
        #
        #   we just have to try parsing the table header one way to determine
        #   if its the old (say, a 'v1') table, or the new 'v2' table.
        #

        try:

            # seperate 'version X' and 'count Y' from each other ('v2')
            version_data, count_data = field_data.split(", ")

        # failure to unpack indicates this is an 'older, v1' drcov log
        except ValueError:
            self.module_table_count   = int(field_data)
            self.module_table_version = 1
            return

        # parse module table version out of 'version X'
        data_name, version = version_data.split(" ")
        #assert data_name == "version"
        self.module_table_version = int(version)
        if not self.module_table_version in [2, 3, 4]:
            raise ValueError("Unsupported (new?) drcov log format...")

        # parse module count in table from 'count Y'
        data_name, count = count_data.split(" ")
        #assert data_name == "count"
        self.module_table_count = int(count)

    def _parse_module_table_columns(self, f):
        """
        Parse drcov log module table columns from filestream.

        -------------------------------------------------------------------

        DynamoRIO v6.1.1, table version 1:
           eg: (Not present)

        DynamoRIO v7.0.0-RC1, table version 2:
           Windows:
             'Columns: id, base, end, entry, checksum, timestamp, path'
           Mac/Linux:
             'Columns: id, base, end, entry, path'

        DynamoRIO v7.0.17594B, table version 3:
           Windows:
             'Columns: id, containing_id, start, end, entry, checksum, timestamp, path'
           Mac/Linux:
             'Columns: id, containing_id, start, end, entry, path'

        DynamoRIO v7.0.17640, table version 4:
           Windows:
             'Columns: id, containing_id, start, end, entry, offset, checksum, timestamp, path'
           Mac/Linux:
             'Columns: id, containing_id, start, end, entry, offset, path'

        """

        # NOTE/COMPAT: there is no 'Columns' line for the v1 table...
        if self.module_table_version == 1:
            return

        # parse module table 'columns'
        #   eg: Columns: id, base, end, entry, checksum, timestamp, path
        column_line = f.readline().strip()
        field_name, field_data = column_line.split(": ")
        #assert field_name == "Columns"

        # seperate column names
        #   Windows:   id, base, end, entry, checksum, timestamp, path
        #   Mac/Linux: id, base, end, entry, path
        columns = field_data.split(", ")

    def _parse_module_table_modules(self, f):
        """
        Parse drcov log modules in the module table from filestream.
        """

        # loop through each *expected* line in the module table and parse it
        for i in xrange(self.module_table_count):
            module = DrcovModule(f.readline().strip(), self.module_table_version)
            self.modules.append(module)

    def _parse_bb_table(self, f):
        """
        Parse dcov log basic block table from filestream.
        """
        self._parse_bb_table_header(f)
        self._parse_bb_table_entries(f)

    def _parse_bb_table_header(self, f):
        """
        Parse drcov log basic block table header from filestream.
        """

        # parse basic block table 'header'
        #   eg: BB Table: 2792 bbs
        header_line = f.readline().strip()
        field_name, field_data = header_line.split(": ")
        #assert field_name == "BB Table"

        # parse basic block count out of 'X bbs'
        count_data, data_name = field_data.split(" ")
        #assert data_name == "bbs"
        self.bb_table_count = int(count_data)

        # peek at the next few bytes to determine if this is a binary bb table.
        # An ascii bb table will have the line: 'module id, start, size:'
        token = "module id"
        saved_position = f.tell()

        # is this an ascii table?
        if f.read(len(token)) == token:
            self.bb_table_is_binary = False

        # nope! binary table
        else:
            self.bb_table_is_binary = True

        # seek back to the start of the table
        f.seek(saved_position)

    def _parse_bb_table_entries(self, f):
        """
        Parse drcov log basic block table entries from filestream.
        """
        # allocate the ctypes structure array of basic blocks
        self.basic_blocks = (DrcovBasicBlock * self.bb_table_count)()

        if self.bb_table_is_binary:
            # read the basic block entries directly into the newly allocated array
            f.readinto(self.basic_blocks)

        else:  # let's parse the text records
            text_entry = f.readline().strip()

            if text_entry != "module id, start, size:":
                raise ValueError("Invalid BB header: %r" % text_entry)

            pattern = re.compile(r"^module\[\s*(?P<mod>[0-9]+)\]\:\s*(?P<start>0x[0-9a-f]+)\,\s*(?P<size>[0-9]+)$")
            for basic_block in self.basic_blocks:
                text_entry = f.readline().strip()

                match = pattern.match(text_entry)
                if not match:
                    raise ValueError("Invalid BB entry: %r" % text_entry)

                basic_block.start = int(match.group("start"), 16)
                basic_block.size = int(match.group("size"), 10)
                basic_block.mod_id = int(match.group("mod"), 10)

#------------------------------------------------------------------------------
# drcov module parser
#------------------------------------------------------------------------------

class DrcovModule(object):
    """
    Parser & wrapper for module details as found in a drcov coverage log.

    A 'module' in this context is a .EXE, .DLL, ELF, MachO, etc.
    """
    def __init__(self, module_data, version):
        self.id    = 0
        self.base  = 0
        self.end   = 0
        self.size  = 0
        self.entry = 0
        self.checksum  = 0
        self.timestamp = 0
        self.path      = ""
        self.filename  = ""
        self.containing_id = 0

        # parse the module
        self._parse_module(module_data, version)

    @property
    def start(self):
        """
        Compatability alias for the module base.

        DrCov table version 2 --> 3 changed this paramter name base --> start.
        """
        return self.base

    def _parse_module(self, module_line, version):
        """
        Parse a module table entry.
        """
        data = module_line.split(", ")

        # NOTE/COMPAT
        if version == 1:
            self._parse_module_v1(data)
        elif version == 2:
            self._parse_module_v2(data)
        elif version == 3:
            self._parse_module_v3(data)
        elif version == 4:
            self._parse_module_v4(data)
        else:
            raise ValueError("Unknown module format (v%u)" % version)

    def _parse_module_v1(self, data):
        """
        Parse a module table v1 entry.
        """
        self.id       = int(data[0])
        self.size     = int(data[1])
        self.path     = str(data[2])
        self.filename = os.path.basename(self.path)

    def _parse_module_v2(self, data):
        """
        Parse a module table v2 entry.
        """
        self.id        = int(data[0])
        self.base      = int(data[1], 16)
        self.end       = int(data[2], 16)
        self.entry     = int(data[3], 16)
        if len(data) == 7: # Windows Only
            self.checksum  = int(data[4], 16)
            self.timestamp = int(data[5], 16)
        self.path      = str(data[-1])
        self.size      = self.end-self.base
        self.filename  = os.path.basename(self.path)

    def _parse_module_v3(self, data):
        """
        Parse a module table v3 entry.
        """
        self.id            = int(data[0])
        self.containing_id = int(data[1])
        self.base          = int(data[2], 16)
        self.end           = int(data[3], 16)
        self.entry         = int(data[4], 16)
        if len(data) > 7: # Windows Only
            self.checksum  = int(data[5], 16)
            self.timestamp = int(data[6], 16)
        self.path          = str(data[-1])
        self.size          = self.end-self.base
        self.filename      = os.path.basename(self.path)

    def _parse_module_v4(self, data):
        """
        Parse a module table v4 entry.
        """
        self.id            = int(data[0])
        self.containing_id = int(data[1])
        self.base          = int(data[2], 16)
        self.end           = int(data[3], 16)
        self.entry         = int(data[4], 16)
        self.offset        = int(data[5], 16)
        if len(data) > 8: # Windows Only
            self.checksum  = int(data[6], 16)
            self.timestamp = int(data[7], 16)
        self.path          = str(data[-1])
        self.size          = self.end-self.base
        self.filename      = os.path.basename(self.path)

#------------------------------------------------------------------------------
# drcov basic block parser
#------------------------------------------------------------------------------

class DrcovBasicBlock(Structure):
    """
    Parser & wrapper for basic block details as found in a drcov coverage log.

    NOTE:

      Based off the C structure as used by drcov -

        /* Data structure for the coverage info itself */
        typedef struct _bb_entry_t {
            uint   start;      /* offset of bb start from the image base */
            ushort size;
            ushort mod_id;
        } bb_entry_t;

    """
    _pack_   = 1
    _fields_ = [
        ('start',  c_uint32),
        ('size',   c_uint16),
        ('mod_id', c_uint16)
    ]

#------------------------------------------------------------------------------
# Command Line Testing
#------------------------------------------------------------------------------

if __name__ == "__main__":
    argc = len(sys.argv)
    argv = sys.argv

    # base usage
    if argc < 2:
        print "usage: %s <coverage filename>" % os.path.basename(sys.argv[0])
        sys.exit()

    # attempt file parse
    x = DrcovData(argv[1])
    for bb in x.basic_blocks:
        print "0x%08x" % bb.start
