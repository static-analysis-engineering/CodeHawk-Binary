# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2024 Aarno Labs LLC
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
import time

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence


class SearchTimeoutException(Exception):

    def __init__(self, timespent: float) -> None:
        self.timespent = timespent

    def __str__(self) -> str:
        return 'timeout at ' + str(self.timespent)


class DirectedGraph:

    def __init__(self, nodes: Sequence[str], edges: Mapping[str, Sequence[str]]):
        self.nodes = nodes
        self.edges = edges    # adjacency list: n -> [ n ]
        self.paths: List[List[str]] = []
        self.maxtime: Optional[float] = None
        self.starttime = 0.0

    def get_paths(self) -> List[List[str]]:
        return self.paths

    def find_paths_aux(
            self,
            src: str,
            dst: Optional[str],
            visited: Dict[str, bool],
            path: List[str],
            depth: int = 0) -> None:
        visited[src] = True
        path.append(src)
        if not dst and (src not in self.edges):
            self.paths.append(path[:])
        elif src == dst:
            self.paths.append(path[:])
        elif src in self.edges:
            for d in self.edges[src]:
                if not visited[d]:
                    self.find_paths_aux(d, dst, visited, path, depth + 1)
        path.pop()
        visited[src] = False
        if self.maxtime:
            timespent = time.time() - self.starttime
            if timespent > self.maxtime:
                raise SearchTimeoutException(timespent)

    def find_paths(
            self,
            src: str,
            dst: Optional[str] = None,
            maxtime: Optional[float] = None) -> None:
        self.starttime = time.time()
        self.maxtime = maxtime
        visited = {}
        for n in self.nodes:
            visited[n] = False
        try:
            self.find_paths_aux(src, dst, visited, [])
        except SearchTimeoutException as e:
            print(str(e))


@dataclass
class DisjointSetNode:
    x: str
    parent: str
    rank: int

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, DisjointSetNode):
            return False

        if self.x != other.x:
            return False

        if self.parent != other.parent:
            return False

        if self.rank != other.rank:
            return False

        return True


class DisjointSetStructure:
    """Simple implementation of union-find data structure.

    Loosely based on:
    https://en.wikipedia.org/wiki/Disjoint-set_data_structure
    """

    def __init__(self) -> None:
        self._forest: Dict[str, DisjointSetNode] = {}

    @property
    def forest(self) -> Dict[str, DisjointSetNode]:
        return self._forest

    def makeset(self, x: str) -> DisjointSetNode:
        if x not in self.forest:
            self._forest[x] = DisjointSetNode(x, x, 0)
            return self.forest[x]
        else:
            raise Exception("Error in DisjointSetStructure.makeset")

    def find(self, x: str) -> DisjointSetNode:
        if x not in self.forest:
            return self.makeset(x)
        else:
            root = self.forest[x]
            while self.forest[root.parent] != root:
                root = self.forest[root.parent]

            return root

    def union(self, x: str, y: str) -> None:
        xnode = self.find(x)
        ynode = self.find(y)

        if xnode == ynode:
            return

        if xnode.rank < ynode.rank:
            lrnode = xnode
            hrnode = ynode
        else:
            lrnode = ynode
            hrnode = xnode

        # make hrnode the new root
        lrnode = DisjointSetNode(lrnode.x, hrnode.x, lrnode.rank)
        self._forest[lrnode.x] = lrnode

        # update parent rank if both nodes have the same rank
        if lrnode.rank == hrnode.rank:
            hrnode = DisjointSetNode(hrnode.x, hrnode.parent, hrnode.rank + 1)
            self._forest[hrnode.x] = hrnode

    def disjoint_sets(self) -> List[List[str]]:
        result: Dict[str, List[str]] = {}
        for (x, n) in self.forest.items():
            if n.x == n.parent:
                result.setdefault(n.x, [])
                if n.x not in result[n.x]:
                    result[n.x].append(n.x)
            else:
                result.setdefault(n.parent, [])
                if n.x not in result[n.parent]:
                    result[n.parent].append(n.x)
        return list(result.values())

    def __str__(self) -> str:
        lines: List[str] = []
        for (x, n) in sorted(self.forest.items()):
            lines.append(x + ": " + str(n))
        return "\n".join(lines)


def coalesce_lists(lsts: List[List[str]]) -> List[List[str]]:
    djstruct = DisjointSetStructure()
    for lst in lsts:
        if len(lst) == 1:
            djstruct.find(lst[0])
        elif len(lst) > 1:
            fst = lst[0]
            for e in lst[1:]:
                djstruct.union(fst, e)
    return djstruct.disjoint_sets()
