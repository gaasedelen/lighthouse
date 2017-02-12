import collections

import idaapi

class IDACoverage(object):
    def __init__(self, base, coverage_data):
        self.functions = {}
        self.base = base
        self._coverage_data = normalize_coverage(coverage_data)
        self.node_map, self.orphans = map_coverage_to_nodes(base, self._coverage_data)

    def _filter_coverage(self):
        pass

    def _dedup_coverage(self):
        pass

    def _coalesce_coverage(self):
        pass

def normalize_coverage(coverage_data):
    """
    Extract the coverage blocks specific to the current database.
    """
    root_filename = idaapi.get_root_filename()

    # locate the coverage that matches the loaded executable
    mod_id = idaapi.BADADDR
    for module in coverage_data.modules:

        # found a module name in the coverage matching this database
        if module.filename == root_filename:
            mod_id = module.id
            break

    # failed to find module matching IDB root filename, bail
    else:
        raise ValueError("Failed to find matching module for this database")

    # loop through the coverage data and filter out data for only this module
    coverage_blocks = []
    for bb in coverage_data.basic_blocks:
        if bb.mod_id == mod_id:
            coverage_blocks.append((bb.start, bb.size))

    return coverage_blocks

def map_coverage_to_nodes(base, coverage_blocks):
    """
    Map block based coverage data to database defined basic blocks (nodes).

    Input:
     - base:
         the imagebase to rebase coverage_blocks to
     - coverage_blocks:
         a list of tuples in (offset, size) format that define coverage

    -----------------------------------------------------------------------

    Output:
     - a tuple of (node_map, orphans)
         read comments below for more details

    """

    #
    # The purpose of this mega while loop is to process the raw block
    # based coverage data and build a comprehensive mapping of nodes
    # throughout the database that are tainted by it.
    #
    # This loop will produce two outputs:
    #

    # node_map is keyed with a function address, and lists tainted nodes.
    node_map = {} # functionEA -> set(tainted node ids)

    # orphans is a list of tuples (offset, size) of coverage that could
    # not be mapped into any defined basic blocks.
    orphans  = [] # [(offset, size), ...]

    # NOTE/PERF: we're cloning a potentially large list here
    blocks = collections.deque(coverage_blocks)
    while blocks:

        # pop off the next coverage block, and compute its rebased address
        offset, size = blocks.popleft()
        address = base + offset

        # TODO/NOTE/PERF: consider caching these lookups below
        # find the function & graph the coverage block *should* fall in
        function  = idaapi.get_func(address)
        flowchart = idaapi.FlowChart(function)

        # find the basic block (node) that our coverage block must start in
        for bb in flowchart:

            # the coverage block (address) starts in this basic block
            if bb.startEA <= address < bb.endEA:

                #
                # first, we need to save this basic block id as we know it
                # definitely is hit by some part of our coverage block
                #

                # add the bb (node) id to an existing function mapping
                try:
                    node_map[function.startEA].add(bb.id)

                # function -> set mapping doesn't exist yet, create it now
                except KeyError as e:
                    node_map[function.startEA] = set([bb.id])

                #
                # depending on coverage & bb quality, we also check for
                # the possibility of a fragment due to the coverage block
                # spilling into the next basic block.
                #

                # does the coverage block spill past this basic block?
                end_address = address + size
                if end_address > bb.endEA:

                    # yes, compute the fragment size and prepend the work
                    # to be consumed later (next iteration, technically)
                    fragment_offset = bb.endEA - base
                    fragment_size   = end_address - bb.endEA
                    blocks.appendleft((fragment_offset, fragment_size))

                # all done, break from the bb for loop
                break

            # end of if statement

        # end of for loop

        #
        # We made it through the entire flowchart for this function without
        # finding an appropriate basic block (node) for the coverage data.
        # this is strange, but whatever... just log the fragment as an
        # orphan for later investigation.
        #

        else:
            orphans.append((offset, size))

    # end of while loop

    # return the resulting goods
    return (node_map, orphans)
