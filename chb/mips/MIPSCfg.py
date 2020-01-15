# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
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

from chb.mips.MIPSCfgBlock import MIPSCfgBlock

class MIPSCfg(object):

    def __init__(self,mipsf,xnode):
        self.mipsfunction = mipsf
        self.xnode = xnode
        self.blocks = {}   #  startaddr -> MIPSCfgBlock
        self.edges = {}    #  srcaddr -> [ tgtaddresses ]  (if multiple, first is false branch)
        self._initialize()

    def get_successors(self,src):
        if src in self.edges:
            return self.edges[src]
        else:
            return []

    def get_loop_levels(self,baddr):
        if baddr in self.blocks:
            return self.blocks[baddr].get_loop_levels()
        return []

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
