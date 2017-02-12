#!/usr/bin/python

import os
import sys
import struct

#------------------------------------------------------------------------------
# drcov log parser
#------------------------------------------------------------------------------

class DrcovData(object):
    """
    DrcovData
    """
    def __init__(self, filepath=None):

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

    def filter_by_module(self, module_name):
        """
        Extract coverage blocks pertaining to the named module.
        """

        # locate the coverage that matches the given module_name
        for module in self.modules:
            if module.filename == module_name:
                mod_id = module.id
                break

        # failed to find a module that matches the given name, bail
        else:
            raise ValueError("Failed to find matching module in coverage")

        # loop through the coverage data and filter out data for only this module
        coverage_blocks = []
        for bb in self.basic_blocks:
            if bb.mod_id == mod_id:
                coverage_blocks.append((bb.start, bb.size))

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
        pass # TODO

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
        """

        # parse module table 'header'
        #   eg: Module Table: version 2, count 11
        header_line = f.readline().strip()
        field_name, field_data = header_line.split(": ")
        #assert field_name == "Module Table"

        # seperate 'version X' and 'count Y' from each other
        version_data, count_data = field_data.split(", ")

        # parse module table version out of 'version X'
        data_name, version = version_data.split(" ")
        #assert data_name == "version"
        self.module_table_version = int(version)

        # parse module count in table from 'count Y'
        data_name, count = count_data.split(" ")
        #assert data_name == "count"
        self.module_table_count = int(count)

    def _parse_module_table_columns(self, f):
        """
        Parse drcov log module table columns from filestream.
        """

        # parse module table 'columns'
        #   eg: Columns: id, base, end, entry, checksum, timestamp, path
        column_line = f.readline().strip()
        field_name, field_data = column_line.split(": ")
        #assert field_name == "Columns"

        # seperate column names
        #   eg: id, base, end, entry, checksum, timestamp, path
        columns = field_data.split(", ")
        #if self.module_table_version == 2:
            #assert columns == ["id", "base", "end", "entry", "checksum", "timestamp", "path"]

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
            f.readline() # yep, so dispose of the rest of this line

        # nope! binary table, seek back to the start of the table
        else:
            self.bb_table_is_binary = True
            f.seek(saved_position)

    def _parse_bb_table_entries(self, f):
        """
        Parse drcov log basic block table entries from filestream.
        """

        # loop through each *expected* line/blob in the bb table and parse it
        for i in xrange(self.bb_table_count):

            # parse the current filestream data into a new basic block
            if self.bb_table_is_binary:
                basic_block = DrcovBasicBlock(f.read(DrcovBasicBlock.BYTESIZE))
            else:
                basic_block = DrcovBasicBlock(f.readline().strip(), binary=False)

            # save the parsed block
            self.basic_blocks.append(basic_block)

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
        self.entry = 0
        self.checksum  = 0
        self.timestamp = 0
        self.path      = ""
        self.filename  = ""

        # parse the module
        self._parse_module(module_data, version)

    def _parse_module(self, module_line, version):
        """
        Parse a Module Table v2 line.
        """

        if version == 2:
            data = module_line.split(", ")

            # parse the individual fields from the module specification line
            self.id        = int(data[0])
            self.base      = int(data[1], 16)
            self.end       = int(data[2], 16)
            self.entry     = int(data[3], 16)
            self.checksum  = int(data[4], 16)
            self.timestamp = int(data[5], 16)
            self.path      = str(data[6])
            self.filename  = os.path.basename(self.path)

        # unknown format
        else:
            raise ValueError("Unknown module format (v%u)" % version)

#------------------------------------------------------------------------------
# drcov basic block parser
#------------------------------------------------------------------------------

class DrcovBasicBlock(object):
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
    BYTESIZE = 4 + 2 + 2 # uint + short + short

    def __init__(self, bb_data, binary=True):

        # basic block fields
        self.start  = 0
        self.size   = 0
        self.mod_id = 0

        # parse the basic block data
        if binary:
            self._parse_bb_binary(bb_data)
        else:
            self._parse_bb_ascii(bb_data)

    def _parse_bb_binary(self, bb_data):
        """
        Parse a binary basic block entry.
        """
        assert len(bb_data) == self.BYTESIZE
        self.start,  = struct.unpack('<I', bb_data[0:4])
        self.size,   = struct.unpack('<H', bb_data[4:6])
        self.mod_id, = struct.unpack('<H', bb_data[6:8])

    def _parse_bb_ascii(self, bb_line):
        """
        Parse an ascii basic block entry.
        """
        raise ValueError("TODO: implement ascii/text bb_entry_t parsing")

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


