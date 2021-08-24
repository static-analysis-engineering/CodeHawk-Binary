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

from typing import cast, Dict, List, Mapping, Optional, Sequence, Set

from chb.api.CallTarget import CallTarget, StubTarget, AppTarget

import chb.util.fileutil as UF
import chb.util.graphutil as UG


class CallgraphNode:
    """Super class for different types of nodes in a call graph.

    The name is assumed to be a unique index for the node, such that it can be
    used in the representation of edges. The __str__ method produces the
    textual content of the node (e.g., in dot).
    """

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_app_node(self) -> bool:
        return False

    @property
    def is_lib_node(self) -> bool:
        return False

    @property
    def is_unknown_tgt(self) -> bool:
        return False

    def __str__(self) -> str:
        return self.name


class AppCallgraphNode(CallgraphNode):

    def __init__(self, address: str, fname: Optional[str]) -> None:
        CallgraphNode.__init__(self, address)
        self._fname = fname

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AppCallgraphNode):
            return self.name == other.name
        return False

    def fname(self) -> str:
        if self._fname:
            return self._fname
        else:
            raise UF.CHBError(
                "Callgraph node for "
                + self.name
                + " does not have a function name")

    def has_fname(self) -> bool:
        return self._fname is not None

    @property
    def is_app_node(self) -> bool:
        return True

    def __str__(self) -> str:
        if self.has_fname():
            return self.fname()
        else:
            return self.name


class LibCallgraphNode(CallgraphNode):

    def __init__(self, name: str) -> None:
        CallgraphNode.__init__(self, name)

    @property
    def is_lib_node(self) -> bool:
        return True

    def __eq__(self, other: object) -> bool:
        if isinstance(other, LibCallgraphNode):
            return self.name == other.name
        return False


class UnknownCallgraphNode(CallgraphNode):

    def __init__(self, id: int, callsite: str) -> None:
        CallgraphNode.__init__(self, "unknown-" + str(id))
        self._id = id
        self._callsite = callsite

    @property
    def id(self) -> int:
        return self._id

    @property
    def callsite(self) -> str:
        """Return hex address of call instruction."""

        return self._callsite

    @property
    def is_unknown_tgt(self) -> bool:
        return True

    def __eq__(self, other: object) -> bool:
        if isinstance(other, UnknownCallgraphNode):
            return self.id == other.id
        return False

    def __str__(self) -> str:
        return "unknown"


class CallgraphEdge:

    def __init__(self, src: str, dst: str) -> None:
        self._src = src
        self._dst = dst

    @property
    def src(self) -> str:
        return self._src

    @property
    def dst(self) -> str:
        return self._dst


class Callgraph:
    """Application call graph.

    The callgraph is incrementally constructed by adding nodes and edges.
    """

    unknowntgtcounter = 0

    def __init__(self) -> None:
        self._nodes: Dict[str, CallgraphNode] = {}
        self._edges: Dict[str, Dict[str, CallgraphEdge]] = {}

    def clone(self, reverse=False) -> "Callgraph":
        result = Callgraph()
        for n in self.nodes.values():
            result.add_node(n)
        for (src, dsts) in self.edges.items():
            srcnode = self.nodes[src]
            for dst in dsts:
                dstnode = self.nodes[dst]
                if reverse:
                    result.add_edge(dstnode, srcnode)
                else:
                    result.add_edge(srcnode, dstnode)
        return result

    @property
    def nodes(self) -> Mapping[str, CallgraphNode]:
        return self._nodes

    @property
    def edges(self) -> Mapping[str, Mapping[str, CallgraphEdge]]:
        return self._edges

    @property
    def edgecount(self) -> int:
        return len(self.edges)

    def add_node(self, node: CallgraphNode) -> None:
        if node.name not in self._nodes:
            self._nodes[node.name] = node

    def has_node(self, node: CallgraphNode) -> bool:
        return node.name in self.nodes

    def add_edge(self, src: CallgraphNode, dst: CallgraphNode) -> None:
        self.add_node(src)
        self.add_node(dst)
        self._edges.setdefault(src.name, {})
        if dst.name not in self._edges[src.name]:
            self._edges[src.name][dst.name] = CallgraphEdge(src.name, dst.name)

    def has_edge(self, src: str, dst: str) -> bool:
        return src in self.edges and dst in self.edges[src]

    def is_root_node(self, name: str) -> bool:
        for (src, dsts) in self.edges.items():
            if name in dsts:
                return False
        else:
            return True

    def is_sink_node(self, name: str) -> bool:
        return name not in self.edges

    def constrain_sources(self, sources: List[str]) -> "Callgraph":
        result = Callgraph()

        def is_source(node: CallgraphNode) -> bool:
            return node.name in sources or str(node) in sources

        for n in self.nodes.values():
            if is_source(n):
                result.add_node(n)

        edgesadded: bool = False
        for (src, dsts) in self.edges.items():
            for dst in dsts:
                if result.has_node(self.nodes[src]) and not result.has_edge(src, dst):
                    result.add_edge(self.nodes[src], self.nodes[dst])
                    edgesadded = True

        while edgesadded:
            edgesadded = False
            for (src, dsts) in self.edges.items():
                for dst in dsts:
                    if result.has_node(self.nodes[src]) and not result.has_edge(src, dst):
                        result.add_edge(self.nodes[src], self.nodes[dst])
                        edgesadded = True
        return result

    def constrain_sinks(self, sinks: List[str]) -> "Callgraph":
        return self.clone(reverse=True).constrain_sources(sinks).clone(reverse=True)


# Convenience functions

def mk_tgt_callgraph_node(iaddr: str, tgt: CallTarget) -> CallgraphNode:
    if tgt.is_app_target:
        tgt = cast(AppTarget, tgt)
        fname: Optional[str] = None
        if tgt.has_tgt_name():
            fname = tgt.tgt_name()
        return AppCallgraphNode(str(tgt.address), fname)
    elif tgt.is_dll_target or tgt.is_so_target or tgt.is_syscall_target:
        tgt = cast(StubTarget, tgt)
        return LibCallgraphNode(tgt.name)
    elif tgt.is_unknown:
        Callgraph.unknowntgtcounter += 1
        return UnknownCallgraphNode(Callgraph.unknowntgtcounter, iaddr)
    else:
        raise UF.CHBNotImplementedError("Callgraph", "mk_callgraph_node", str(tgt))


def mk_app_callgraph_node(addr: str, fname: Optional[str]) -> CallgraphNode:
    return AppCallgraphNode(addr, fname)
