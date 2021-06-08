# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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

from typing import Callable, Dict, List, Set

import chb.util.graphutil as UG

from chb.app.Callgraph import Callgraph
from chb.util.DotGraph import DotGraph


class DotCallgraph:

    def __init__(
            self,
            graphname: str,
            callgraph: Callgraph,
            sinks: List[str] = [],
            startaddr: str = None,
            getcolor: Callable[[str], str] = lambda x: "purple",
            getname: Callable[[str], str] = lambda x: x) -> None:
        self.graphname = graphname
        self.callgraph = callgraph
        self.dotgraph = DotGraph(graphname)
        self.dotgraph.rankdir = 'LR'
        self.sinks = sinks
        self.startaddr = startaddr
        self.getcolor = getcolor
        self.getname = getname
        self._pathnodes: Set[str] = set([])

        if self.startaddr and not self.sinks:
            self.restrict_nodes_from(self.startaddr)
        else:
            self.restrict_nodes()

    def build(self) -> DotGraph:
        if len(self.sinks) > 0:
            self.restrict_nodes()
        for n in self.callgraph.nodes():
            if self.getcolor(n) is None:
                continue
            self.add_cg_node(n, self.getcolor(n))
            for d in self.callgraph.edgelist()[n]:
                self.add_cg_edge(
                    n, d, self.callgraph.edges()[n][d], self.getcolor(n))
        return self.dotgraph

    def restrict_nodes(self) -> None:
        nodes = set([])
        edges: Dict[str, List[str]] = {}
        for n in self.callgraph.nodes():
            nodes.add(n)
            for d in self.callgraph.edgelist()[n]:
                nodes.add(d)
                edges.setdefault(n, [])
                edges[n].append(d)
        if self.startaddr is None:
            self.pathnodes = nodes
            return
        g = UG.DirectedGraph(list(nodes), edges)
        if len(self.sinks) > 0:
            g.find_paths(self.startaddr, self.sinks[0])
            for p in g.paths:
                print('Path: ' + str(p))
                self.pathnodes = self.pathnodes.union(p)
            if len(self.pathnodes) == 0:
                self.pathnodes = nodes
        else:
            self.pathnodes = nodes

    def restrict_nodes_from(self, startaddr: str) -> None:
        nodes = set([])
        edges: Dict[str, List[str]] = {}
        nodes.add(startaddr)
        for d in self.callgraph.edgelist()[startaddr]:
            nodes.add(d)
            edges.setdefault(startaddr, [])
            edges[startaddr].append(d)
        nodecount = len(nodes)
        while True:
            for n in self.callgraph.nodes():
                if n in nodes:
                    for d in self.callgraph.edgelist()[n]:
                        nodes.add(d)
                        edges.setdefault(n, [])
                        edges[n].append(d)
            if len(nodes) == nodecount:
                break
            nodecount = len(nodes)
        self.pathnodes = nodes

    def add_cg_node(self, n: str, color: str) -> None:
        blocktxt = self.getname(str(n))
        if str(n) in self.pathnodes:
            self.dotgraph.add_node(str(n), labeltxt=blocktxt, color=color)

    def add_cg_edge(self, n: str, d: str, count: int, color: str) -> None:
        labeltxt = str(count)
        if self.getcolor(d) is None:
            return
        if str(n) in self.pathnodes and str(d) in self.pathnodes:
            blocktxt = self.getname(str(d))
            self.dotgraph.add_node(str(d), labeltxt=blocktxt, color=self.getcolor(d))
            self.dotgraph.add_edge(str(n), str(d))
