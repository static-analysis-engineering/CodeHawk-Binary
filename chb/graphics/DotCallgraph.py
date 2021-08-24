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

from chb.app.Callgraph import Callgraph, CallgraphNode
from chb.util.DotGraph import DotGraph


class DotCallgraph:

    def __init__(
            self,
            graphname: str,
            callgraph: Callgraph,
            reverse: bool = False,
            getcolor: Callable[[CallgraphNode], str] = lambda x: "lightblue",
            nodefilter: Callable[[CallgraphNode], bool] = lambda x: True,
            samerank: List[Callable[[CallgraphNode], bool]] = []) -> None:
        self._graphname = graphname
        self._callgraph = callgraph
        self._reverse = reverse
        self._dotgraph = DotGraph(graphname)
        self._dotgraph.rankdir = "LR"
        self._getcolor = getcolor
        self._nodefilter = nodefilter
        self._samerank = samerank
        """
        if self.startaddr and not self.sinks:
            self.restrict_nodes_from(self.startaddr)
        else:
            self.restrict_nodes()
        """

    @property
    def callgraph(self) -> Callgraph:
        return self._callgraph

    @property
    def dotgraph(self) -> DotGraph:
        return self._dotgraph

    @property
    def reverse(self) -> bool:
        return self._reverse

    def nodecolor(self, node: CallgraphNode) -> str:
        return self._getcolor(node)

    def nodefilter(self, node: CallgraphNode) -> bool:
        return self._nodefilter(node)

    @property
    def samerank(self) -> List[Callable[[CallgraphNode], bool]]:
        return self._samerank

    def to_dotgraph(self) -> DotGraph:
        nodes = self.callgraph.nodes
        for (name, node) in nodes.items():
            if self.nodefilter(node):
                self.dotgraph.add_node(
                    name, labeltxt=str(node), color=self.nodecolor(node))
        for (src, edges) in self.callgraph.edges.items():
            for (dst, dstedge) in edges.items():
                if self.nodefilter(nodes[src]) and self.nodefilter(nodes[dst]):
                    if self.reverse:
                        self.dotgraph.add_edge(dst, src)
                    else:
                        self.dotgraph.add_edge(src, dst)
        for r in self.samerank:
            sameranknodes: List[str] = []
            for (name, node) in nodes.items():
                if self.nodefilter(node) and r(node):
                    sameranknodes.append(name)
            self.dotgraph.set_same_rank(sameranknodes)
        return self.dotgraph
