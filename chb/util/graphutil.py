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
import time

from typing import Dict, List, Mapping, Optional, Sequence


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
