# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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

import chb.util.graphutil as UG

class Callgraph(object):

    def __init__(self,app):
        self.app = app
        self.nodes = set([])
        self.edges = {}            # faddr -> faddr/name -> int
        self.revedges = {}         # faddr/name -> faddr -> int
        self._initialize()

    def get_name(self,n):
        if self.app.has_function_name(n):
            return self.app.get_function_name(n)
        else:
            return n

    def reverse_edges(self):
        if len(self.revedges) == 0:
            for src in self.edges:
                for dst in self.edges[src]:
                    self.revedges.setdefault(dst,{})
                    self.revedges[dst].setdefault(src,0)
                    self.revedges[dst][src] += 1

    def _initialize(self):
        calls = self.app.get_call_instructions()  # faddr -> instr
        for faddr in calls:
            self.nodes.add(faddr)
            self.edges[faddr] = {}
            for instr in calls[faddr]:
                tgt = instr.get_call_target()
                if not tgt is None:
                    tgt = str(tgt)
                    self.nodes.add(tgt)
                    self.edges[faddr].setdefault(tgt,0)
                    self.edges[faddr][tgt] += 1


    def get_paths(self,src,dst):
        g = UG.DirectedGraph(self.nodes,self.edges)
        g.find_paths(src,dst)
        return g.paths

    def get_reverse_paths(self,src):
        self.reverse_edges()
        g = UG.DirectedGraph(self.nodes,self.revedges)
        g.find_paths(src)
        return g.paths

    def get_reverse_callgraph(self):
        self.reverse_edges()
        return self.revedges

