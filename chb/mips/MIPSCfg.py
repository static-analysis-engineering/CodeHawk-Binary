# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ------------------------------------------------------------------------------
"""MIPS Control flow graph."""

import xml.etree.ElementTree as ET

from typing import Dict, TYPE_CHECKING

import chb.app.Cfg as C
import chb.util.fileutil as UF
import chb.util.graphutil as UG

from chb.mips.MIPSCfgBlock import MIPSCfgBlock
from chb.mips.MIPSCfgPath import MIPSCfgPath

if TYPE_CHECKING:
    import chb.mips.MIPSFunction

class MIPSCfg(C.Cfg):

    def __init__(
            self,
            f: "chb.mips.MIPSFunction.MIPSFunction",
            xnode: ET.Element) -> None:
        C.Cfg.__init__(self, f, xnode)
        self._blocks: Dict[str, MIPSCfgBlock] = {}

    @property
    def blocks(self) -> Dict[str, MIPSCfgBlock]:
        if len(self._blocks) == 0:
            xblocks = self.xnode.find('blocks')
            if xblocks is None:
                raise UF.CHBError("Element blocks missing in MIPSCfg")
            for b in xblocks.findall("bl"):
                baddr = b.get("ba")
                if baddr is None:
                    raise UF.CHBError("Attribute ba missing in Cfg block")
                self._blocks[baddr] = MIPSCfgBlock(self, b)
        return self._blocks

    def get_paths(self,baddr,maxtime=None):
        """Returns a path from function entry to blockaddr baddr."""
        g = UG.DirectedGraph(self.blocks.keys(),self.edges)
        g.find_paths(self.function.faddr,baddr,maxtime=maxtime)
        return [ MIPSCfgPath(self,p) for p in g.paths ]

    def get_branch_instruction(self,n):
        block = self.blocks[n]
        iaddr = int(block.lastaddr,16) - 4  #  account for delay slot
        return self.function.get_instruction(hex(iaddr))

    def condition_to_annotated_value(self,src,b):
        result = {}
        ftconditions = b.get_ft_conditions()
        if len(ftconditions) == 2:
            result['c'] = ftconditions[1].to_annotated_value()
            result['fb'] = self.edges[src][0]
            result['tb'] = self.edges[src][1]
        return result

    def get_conditions(self):
        result = {}
        for src in self.edges:
            if len(self.edges[src]) > 1:
                brinstr = self.get_branch_instruction(src)
                result[brinstr.iaddr] = self.condition_to_annotated_value(src,brinstr)
        return result

    def get_condition(self,src,tgt):
        """Returns the condition, if any, that leads from src to tgt."""
        if len(self.edges[src]) > 1:
            brinstr = self.get_branch_instruction(src)
            ftconditions = brinstr.get_ft_conditions()
            if len(ftconditions) == 2:
                for i,t in enumerate(self.edges[src]):
                    if tgt == t:
                        return ftconditions[i]
                else:
                    print('Error in get_condition')

    def get_path_conditions(self,path):
        result = {}
        for i in range(len(path) - 1):
            c = self.get_condition(path[i],path[i+1])
            if c is None:
                continue
            result[path[i]] = c
        return result

    def __str__(self):
        lines = []
        return (str(self.blocks) + '\n' + str(self.edges))

    def _initialize(self):
        self._get_blocks()
        self._get_edges()

    def _get_blocks(self):
        if len(self.blocks) == 0:
            blocks = self.xnode.find('blocks')
            if blocks is None: return
            for b in blocks.findall('bl'):
                self.blocks[b.get('ba')] = MIPSCfgBlock(self,b)

    def _get_edges(self):
        if len(self.edges) == 0:
            edges = self.xnode.find('edges')
            if edges is None: return
            for e in edges.findall('e'):
                src = e.get('src')
                if not src in self.edges: self.edges[src] = []
                self.edges[src].append(e.get('tgt'))
