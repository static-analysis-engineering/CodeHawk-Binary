# ------------------------------------------------------------------------------
# Python API to access CodeHawk Binary Analyzer analysis results
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

import chb.util.graphutil as UG

from chb.util.DotGraph import DotGraph

class DotCallgraph(object):

    def __init__(self,graphname,callgraph,sinks=[],getname=lambda x:x):
        self.graphname = graphname
        self.callgraph = callgraph             # address -> address/name -> count
        self.dotgraph = DotGraph(graphname)
        self.dotgraph.rankdir = 'LR'
        self.sinks = sinks
        self.pathnodes = set([])
        self.getname = getname
        self.restrict_nodes()

    def build(self,coloring=lambda n:'purple'):  # name -> color / None
        if len(self.sinks) > 0:
            self.restrict_nodes()
        for n in self.callgraph:
            if coloring(n) is None: continue
            self.add_cg_node(n,coloring(n))
            for d in self.callgraph[n]:
                self.add_cg_edge(n,d,self.callgraph[n][d],coloring)
        return self.dotgraph

    def restrict_nodes(self,startaddr):
        nodes = set([])
        edges = {}
        for n in self.callgraph:
            nodes.add(n)
            for d in self.callgraph[n]:
                nodes.add(d)
                edges.setdefault(n,[])
                edges[n].append(d)
        g = UG.DirectedGraph(nodes,edges)
        if len(self.sinks) > 0:
            g.find_paths(startaddr,self.sinks[0])
            for p in g.paths:
                print('Path: ' + str(p))
                self.pathnodes = self.pathnodes.union(p)
            if len(self.pathnodes) == 0:
                self.pathnodes = nodes
        else:
            self.pathnodes = nodes

    def add_cg_node(self,n,color):
        blocktxt = self.getname(str(n))
        if str(n) in self.pathnodes:
            self.dotgraph.add_node(str(n),labeltxt=blocktxt,color=color)

    def add_cg_edge(self,n,d,count,coloring=lambda n:'purple'):
        labeltxt = str(count)
        if coloring(d) is None:
            return
        if str(n) in self.pathnodes and str(d) in self.pathnodes:
            self.dotgraph.add_node(str(d),labeltxt=str(d),color=coloring(d))
            self.dotgraph.add_edge(str(n),str(d))
        
