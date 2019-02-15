#!/usr/bin/python

import os
import sys
import mmap
import idaapi
import struct
from ctypes import *
from collections import Counter

# this version is for pe-afl

#------------------------------------------------------------------------------
# drcov log parser
#------------------------------------------------------------------------------

class DrcovData(object):
    """
    A drcov log parser.
    """
    def __init__(self, filepath=None):

        self.filepath = filepath
        self.buf = [int(i, 16) for i in open(filepath).read().strip().split()]
        self.base = idaapi.get_imagebase()

    #--------------------------------------------------------------------------
    # Public
    #--------------------------------------------------------------------------

    def get_bb_and_size(self, graph, ea):
        for block in graph:
            if block.startEA <= ea and block.endEA > ea:
                return (block.startEA-self.base, block.endEA-block.startEA)

    def get_blocks_by_module(self, module_name):
        """
        Extract coverage blocks pertaining to the named module.
        """

        coverage_blocks = []
        for addr in self.buf:
            x = addr
            f = idaapi.get_func(x)
            g = idaapi.FlowChart(f)
            coverage_blocks.append(self.get_bb_and_size(g, x))
            first_block = (g[0].startEA-self.base, g[0].endEA-g[0].startEA)
            if first_block not in coverage_blocks:
                coverage_blocks.append(first_block)

        c = Counter(coverage_blocks)
        for k in c:
            addr = k[0]+self.base
            print hex(addr).strip('L'), c[k]

        return coverage_blocks

#------------------------------------------------------------------------------
# Command Line Testing
#------------------------------------------------------------------------------

if __name__ == "__main__":

    # for testing
    trace_file = 'C:\\Users\\wmliang\\winafl\\test_ioctl\\bin\\trace2.log'

    # attempt file parse
    x = DrcovData(trace_file)
    print x.get_blocks_by_module('')


