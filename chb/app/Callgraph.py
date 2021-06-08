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

from typing import Dict, List, Mapping, Set

import chb.util.graphutil as UG


class Callgraph:

    def __init__(
            self,
            calls: Mapping[str, Mapping[str, int]]) -> None:
        self._nodes: Set[str] = set([])
        # faddr -> faddr/name -> int
        self._edges: Mapping[str, Mapping[str, int]] = calls
        self._edgelist: Dict[str, List[str]] = {}
        # faddr/name -> faddr -> int
        self._revedges: Dict[str, Dict[str, int]] = {}
        self._revedgelist: Dict[str, List[str]] = {}

    def edges(self) -> Mapping[str, Mapping[str, int]]:
        return self._edges

    def edgelist(self) -> Dict[str, List[str]]:
        if len(self._edgelist) == 0:
            for src in self.edges():
                for dst in self.edges()[src]:
                    self._edgelist.setdefault(src, [])
                    self._edgelist[src].append(dst)
        return self._edgelist

    def nodes(self) -> Set[str]:
        if len(self._nodes) == 0:
            for src in self.edges():
                for dst in self.edges()[src]:
                    self._nodes.add(src)
                    self._nodes.add(dst)
        return self._nodes

    def revedges(self) -> Mapping[str, Mapping[str, int]]:
        if len(self._revedges) == 0:
            for src in self.edges():
                for dst in self.edges()[src]:
                    self._revedges.setdefault(dst, {})
                    self._revedges[dst].setdefault(src, 0)
                    self._revedges[dst][src] += self.edges()[src][dst]
        return self._revedges

    def revedgelist(self) -> Dict[str, List[str]]:
        if len(self._revedgelist) == 0:
            for src in self.revedges():
                for dst in self.revedges()[src]:
                    self._revedgelist.setdefault(src, [])
                    self._revedgelist[src].append(dst)
        return self._revedgelist

    def get_paths(self, src: str, dst: str) -> List[List[str]]:
        g = UG.DirectedGraph(list(self.nodes()), self.edgelist())
        g.find_paths(src, dst)
        return g.get_paths()

    def get_reverse_paths(self, src: str) -> List[List[str]]:
        g = UG.DirectedGraph(list(self.nodes()), self.revedgelist())
        g.find_paths(src)
        return g.get_paths()

    def get_reverse_callgraph(self) -> Mapping[str, Mapping[str, int]]:
        return self.revedges()
