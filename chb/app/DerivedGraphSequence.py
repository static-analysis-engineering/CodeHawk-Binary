# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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
"""Representation of control flow graphs as a sequence of interval graphs.

Based on

Frances E. Allen, Control Flow Analysis, SIGPLAN Notices, 1970.
"""

from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple, TYPE_CHECKING

from chb.util.DotGraph import DotGraph
import chb.util.dotutil as UD


class GraphInterval:
    """Maximual single-entry subgraph in which the header node appears in all closed paths."""

    def __init__(self, header: str) -> None:
        self._header = header
        self._nodes: Set[str] = {header}
        self._edges: Dict[str, List[str]] = {}
        self._revedges: Dict[str, List[str]] = {}
        self._rpo: Dict[str, int] = {}
        self._dom: Dict[str, Set[str]] = {}  # dominators
        self._idom: Dict[str, str] = {}  # immediate dominators
        self._twowayconditionals: Dict[str, str] = {}

    @property
    def nodes(self) -> Set[str]:
        return self._nodes

    @property
    def rpo_sorted_nodes(self) -> List[str]:
        rpo = self.rpo
        return sorted(self.nodes, key=lambda n: rpo[n])

    @property
    def rpo_revsorted_nodes(self) -> List[str]:
        rpo = self.rpo
        return sorted(self.nodes, key=lambda n: rpo[n], reverse=True)

    @property
    def edges(self) -> Dict[str, List[str]]:
        return self._edges

    @property
    def header(self) -> str:
        return self._header

    @property
    def revedges(self) -> Dict[str, List[str]]:
        if len(self._revedges) == 0:
            for src in self.edges:
                for tgt in self.edges[src]:
                    self._revedges.setdefault(tgt, [])
                    self._revedges[tgt].append(src)
        return self._revedges

    @property
    def rpo(self) -> Dict[str, int]:
        """Return a mapping from address to index in the reverse postorder"""

        if len(self._rpo) == 0:

            s1: List[str] = []
            s2: List[str] = []

            s1.append(self.header)

            while(s1):
                node = s1.pop()
                if node in s2:
                    s2.remove(node)   # remove earlier visit, keep last one
                s2.append(node)

                for t in sorted(self.post(node)):
                    if t != self.header:
                        s1.append(t)

            for (i, node) in enumerate(s2):
                self._rpo[node] = i

        return self._rpo

    @property
    def dom(self) -> Dict[str, Set[str]]:
        """Return a mapping from nodes to their dominators.

        Note: a graphinterval is guaranteed to be acyclic, except for the
        back-edges to the header (which are not considered here), and thus
        a single forward pass is sufficient to collect the dominators.
        """

        if len(self._dom) == 0:
            self._dom[self.header] = set([self.header])
            for n in self.rpo_sorted_nodes:
                if n == self.header:
                    continue
                self._dom[n] = self.nodes.intersection(
                    *([self._dom[k] for k in self.pre(n)]))
                self._dom[n].add(n)

        return self._dom

    @property
    def idom(self) -> Dict[str, str]:
        """Return mapping from node to its immediate dominator."""

        if len(self._idom) == 0:
            for n in self.dom:
                if n == self.header:
                    continue
                self._idom[n] = max(self.dom[n] - set([n]), key=lambda k: self.rpo[k])
        return self._idom

    @property
    def two_way_conditionals(self) -> Dict[str, str]:
        """Identify 2-way conditionals and their follow nodes.

        Based on algorithm in:
        Cristina Cifuentes, Structuring Decompiled Graphs, Compiler Construction,
        CC'96, LNCS 1060, pg 91-105, Springer, 1996.
        """

        def find_follow(m: str) -> Optional[str]:
            followcandidates: List[str] = [
                i for i in self.nodes
                if i != self.header and self.idom[i] == m and len(self.pre(i)) >= 2]
            if len(followcandidates) > 0:
                return max(followcandidates, key=lambda k: self.rpo[k])
            else:
                return None

        def is_descendant(child: str, parent: str) -> bool:
            for i in self.post(parent):
                if child == i:
                    return True
                if is_descendant(child, i):
                    return True
            return False

        unresolved: Set[str] = set([])

        if len(self._twowayconditionals) == 0:
            for m in self.rpo_revsorted_nodes:
                if (
                        len(self.post(m)) == 2       # 2-way conditional
                        and ((not m == self.header)
                             or len(self.pre(m)) == 0)  # not a loop header
                        and self.header not in self.post(m)):  # not a latching node
                    follow = find_follow(m)
                    if follow is not None:
                        self._twowayconditionals[m] = follow
                        toberemoved: List[str] = []
                        for k in unresolved:
                            if is_descendant(follow, k):
                                self._twowayconditionals[k] = follow
                                toberemoved.append(k)
                        for k in toberemoved:
                            unresolved.remove(k)
                    else:
                        unresolved.add(m)

        if len(unresolved) > 0:
            print("Unresolved two-way conditional: " + ", ".join(unresolved))
        return self._twowayconditionals

    def post(self, n) -> Set[str]:
        if n in self.edges:
            return set(self.edges[n])
        else:
            return set([])

    def pre(self, n) -> Set[str]:
        if n in self.revedges:
            return set(self.revedges[n])
        else:
            return set([])

    def has_node(self, n: str) -> bool:
        return n in self.nodes

    def has_nodes(self, s: Set[str]):
        return s.issubset(self.nodes)

    def add_node(self, n: str) -> None:
        self._nodes.add(n)

    def add_edge(self, src: str, tgt: str) -> None:
        self._edges.setdefault(src, [])
        self._edges[src].append(tgt)

    def __str__(self) -> str:
        return (
            self.header
            + " ("
            + str(len(self.nodes))
            + "): {" + ", ".join(sorted(self.nodes)) + "}")


class IntervalGraph:
    """Graph with intervals of which the nodes may also be intervals.

    It is assumed that the first node given is the unique entry node.
    """

    def __init__(
            self,
            faddr: str,
            nodes: List[str],
            edges: Mapping[str, Sequence[str]]) -> None:
        self._faddr = faddr
        self._nodes = nodes
        self._edges = edges
        self._revedges: Dict[str, List[str]] = {}
        self._intervals: Dict[str, GraphInterval] = {}
        self._revintervals: Dict[str, str] = {}  # maps addr to interval header

    @property
    def faddr(self) -> str:
        return self._faddr

    @property
    def size(self) -> int:
        return len(self.nodes)

    @property
    def nodes(self) -> List[str]:
        return self._nodes

    @property
    def edges(self) -> Mapping[str, Sequence[str]]:
        return self._edges

    @property
    def revedges(self) -> Dict[str, List[str]]:
        if len(self._revedges) == 0:
            for src in self.edges:
                for tgt in self.edges[src]:
                    self._revedges.setdefault(tgt, [])
                    self._revedges[tgt].append(src)
        return self._revedges

    def hrpo(self, prevrpo: Dict[str, List[int]]) -> Dict[str, List[int]]:
        result: Dict[str, List[int]] = {}
        for n in prevrpo:
            if n in self.intervals:
                irpo = self.intervals[n].rpo
                for ni in irpo:
                    result[ni] = prevrpo[n] + [irpo[ni]]
        return result

    @property
    def intervals(self) -> Dict[str, GraphInterval]:
        if len(self._intervals) == 0:
            self._construct_intervals()
        return self._intervals

    @property
    def rev_intervals(self) -> Dict[str, str]:
        if len(self._revintervals) == 0:
            for (h, i) in self.intervals.items():
                for k in i.nodes:
                    self._revintervals[k] = h
        return self._revintervals

    def post(self, n) -> Set[str]:
        if n in self.edges:
            return set(self.edges[n])
        else:
            return set([])

    def pre(self, n) -> Set[str]:
        if n in self.revedges:
            return set(self.revedges[n])
        else:
            return set([])

    @property
    def intervalnodecount(self) -> int:
        """Return the total number of nodes in the intervals."""

        return sum(len(i.nodes) for i in self.intervals.values())

    @property
    def intervalgraph(self) -> Tuple[List[str], Dict[str, List[str]]]:
        """Return the nodes and edges representing the intervals and their relationships."""

        inodes: List[str] = []
        iedges: Set[Tuple[str, str]] = set([])

        headers = [g.header for g in self.intervals.values()]
        if len(headers) == 1:
            return ([headers[0]], {})

        for (header, intv) in self.intervals.items():
            inodes.append(header)
            posti = set([])
            for n in intv.nodes:
                for j in self.post(n):
                    if j not in intv.nodes:
                        posti.add(j)

            for (header2, intv2) in self.intervals.items():
                if header2 == header:
                    continue
                if header2 in posti:
                    iedges.add((header, header2))
                for n in intv2.nodes:
                    for k in self.post(n):
                        if k == header:
                            iedges.add((header2, header))
                            break

        edges: Dict[str, List[str]] = {}
        for (i, j) in iedges:
            edges.setdefault(i, [])
            edges[i].append(j)

        return (inodes, edges)

    def _construct_intervals(self) -> None:
        headers: List[str] = [self.faddr]
        covered: Set[str] = set([])
        while len(headers) > 0:
            h = headers[0]
            headers = headers[1:]
            worklist = [h]
            interval = GraphInterval(h)
            covered.add(h)
            while len(worklist) > 0:
                c = worklist[0]
                worklist = worklist[1:]
                if c in self.edges:
                    for tgt in self.edges[c]:
                        if tgt not in worklist:
                            tgtpre = self.revedges[tgt]
                            if interval.has_nodes(set(tgtpre)):
                                interval.add_node(tgt)
                                worklist.append(tgt)
                                covered.add(tgt)

            for src in self.edges:
                for tgt in self.edges[src]:
                    if interval.has_node(src) and interval.has_node(tgt):
                        interval.add_edge(src, tgt)

            for n in interval.nodes:
                if n in self.edges:
                    for tgt in self.edges[n]:
                        if (
                                not interval.has_node(tgt)
                                and tgt not in headers
                                and tgt not in covered):
                            headers.append(tgt)

            self._intervals[h] = interval

    def to_dot(
            self,
            name: str,
            rpo: Dict[str, List[int]] = {},
            showintervals=False) -> DotGraph:
        dotgraph = DotGraph(name)
        for n in self.nodes:
            if n in rpo:
                index = ":".join(str(i) for i in rpo[n])
                labeltxt = index + ":" + n
            else:
                labeltxt = n
            dotgraph.add_node(n, labeltxt=labeltxt)

        if showintervals:
            clusters: Dict[str, Set[Tuple[str, str]]] = {}
            for src in self.edges:
                for tgt in self.edges[src]:
                    if self.rev_intervals[src] == self.rev_intervals[tgt]:
                        h = self.rev_intervals[src]
                        clusters.setdefault(h, set([]))
                        clusters[h].add((src, tgt))
                    else:
                        dotgraph.add_edge(src, tgt)
            for (h, edges) in clusters.items():
                dotgraph.add_cluster(h, edges)

        else:
            for src in self.edges:
                for tgt in self.edges[src]:
                    dotgraph.add_edge(src, tgt)

        return dotgraph

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Intervals (" + str(len(self.intervals)) + ")")
        for i in sorted(self.intervals):
            lines.append(str(self.intervals[i]))
        return "\n".join(lines)


class DerivedGraphSequence:
    """A sequence of graphs, where each graph is constructed from nodes of the previous graph."""

    def __init__(
            self,
            faddr: str,
            nodes: List[str],
            edges: Mapping[str, Sequence[str]]) -> None:
        self._faddr = faddr
        self._nodes = nodes
        self._edges = edges
        self._graphs: List[IntervalGraph] = []

    @property
    def faddr(self) -> str:
        return self._faddr

    @property
    def nodes(self) -> List[str]:
        """Return the nodes of the original graph (G0)."""

        return self._nodes

    @property
    def rpo_sorted_nodes(self) -> List[str]:
        """Return the nodes of the original graph (G0) in reverse postorder."""

        hrpo = self.hrpo
        return sorted(self.nodes, key=lambda k: hrpo[k])

    @property
    def edges(self) -> Mapping[str, Sequence[str]]:
        """Return the edge mapping of the original graph (G0)."""

        return self._edges

    @property
    def graphs(self) -> List[IntervalGraph]:
        if len(self._graphs) == 0:
            self._construct_derived_graph_sequence()
        return self._graphs

    @property
    def is_reducible(self) -> bool:
        return self.graphs[-1].size == 1

    @property
    def hrpo(self) -> Dict[str, List[int]]:
        """Return hierarchical reverse postorder on all nodes."""

        prevrpo: Dict[str, List[int]] = {}
        if self.graphs[-1].size == 1:
            header = self.graphs[-1].nodes[0]
            prevrpo = {header: [0]}
            for g in self.graphs[:-1][::-1]:
                prevrpo = g.hrpo(prevrpo)
        return prevrpo

    def _construct_derived_graph_sequence(self) -> None:
        g = IntervalGraph(self.faddr, self.nodes, self.edges)
        self._graphs.append(g)
        prevnodecount = len(self.nodes) + 1
        (gnodes, gedges) = g.intervalgraph
        intervalnodecount = g.intervalnodecount
        while len(gnodes) > 1 and intervalnodecount < prevnodecount:
            g = IntervalGraph(self.faddr, gnodes, gedges)
            self._graphs.append(g)
            (gnodes, gedges) = g.intervalgraph
            prevnodecount = intervalnodecount
            intervalnodecount = g.intervalnodecount
        if len(gnodes) == 1:
            g = IntervalGraph(self.faddr, gnodes, gedges)
            self._graphs.append(g)

    def to_dot(self, path: str, out: str):
        rpo = self.graphs[-1].size == 1
        for (i, g) in enumerate(self.graphs):
            pdffilename = UD.print_dot(
                path,
                out + str(i+1),
                g.to_dot("G" + str(i+1), rpo=self.hrpo, showintervals=True))
            print(pdffilename)

    def two_way_conditionals(self) -> Dict[str, str]:
        i = list(self.graphs[0].intervals.values())[0]
        return i.two_way_conditionals

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("\nDerived graph sequence for " + str(len(self.nodes)) + " nodes")
        count = 0
        for g in self.graphs:
            lines.append(str(g))
        return "\n\n".join(lines)
