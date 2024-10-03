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

from typing import (
    Any, Iterable, cast, Dict, List, Mapping, Optional, Sequence, Set)

from chb.api.CallTarget import (
    CallTarget, StubTarget, AppTarget, InlinedAppTarget, CallbackTableTarget)

from chb.jsoninterface.JSONResult import JSONResult

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
    def is_tagged_app_node(self) -> bool:
        return False

    @property
    def is_lib_node(self) -> bool:
        return False

    @property
    def is_call_back_table_node(self) -> bool:
        return False

    @property
    def is_unknown_tgt(self) -> bool:
        return False

    def ids(self) -> List[str]:
        """Returns the different ways in which the node can be identified

        Some node types can be identified by either function name or address
        """
        return [self.name]

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["name"] = self.name
        return JSONResult("cgnode", content, "ok")

    def __str__(self) -> str:
        return self.name


class AppCallgraphNode(CallgraphNode):

    def __init__(self, address: str, fname: Optional[str]) -> None:
        if fname:
            CallgraphNode.__init__(self, fname)
        else:
            CallgraphNode.__init__(self, address)
        self._faddr = address

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AppCallgraphNode):
            return self.name == other.name
        return False

    @property
    def faddr(self) -> str:
        return self._faddr

    def ids(self) -> List[str]:
        return [self.name, self.faddr]

    @property
    def is_app_node(self) -> bool:
        return True


class TaggedAppCallgraphNode(AppCallgraphNode):

    def __init__(self, tag: str, address: str, fname: Optional[str]) -> None:
        AppCallgraphNode.__init__(self, address, fname)
        self._tag = tag

    @property
    def is_tagged_app_node(self) -> bool:
        return True


class InlinedAppCallgraphNode(CallgraphNode):

    def __init__(self, address: str, fname: Optional[str]) -> None:
        if fname:
            CallgraphNode.__init__(self, fname)
        else:
            CallgraphNode.__init__(self, address)
        self._faddr = address

    def __eq__(self, other: object) -> bool:
        if isinstance(other, InlinedAppCallgraphNode):
            return self.name == other.name
        return False

    @property
    def faddr(self) -> str:
        return self._faddr

    @property
    def is_inlined_app_node(self) -> bool:
        return True


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


class CallbackTableCallgraphNode(CallgraphNode):

    def __init__(self, address: str, offset: int) -> None:
        CallgraphNode.__init__(self, str(address) + ":" + str(offset))

    @property
    def is_call_back_table_node(self) -> bool:
        return True


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

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["src"] = self.src
        content["dst"] = self.dst
        return JSONResult("cgedge", content, "ok")


class Callgraph:
    """Application call graph.

    The callgraph is incrementally constructed by adding nodes and edges.
    """

    unknowntgtcounter = 0

    def __init__(self) -> None:
        self._nodes: Dict[str, CallgraphNode] = {}
        self._edges: Dict[str, Dict[str, CallgraphEdge]] = {}

    def clone(self, reverse: bool = False) -> "Callgraph":
        result = Callgraph()
        for n in self.nodes.values():
            result.add_node(n)
        for (src, dsts) in self.edges.items():
            if src in self.nodes:
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
    def nodecount(self) -> int:
        return len(self.nodes)

    @property
    def edgecount(self) -> int:
        return sum (len(self.edges[e]) for e in self.edges)

    def add_node(self, node: CallgraphNode) -> None:
        if not self.has_node(node):
            self._nodes[node.name] = node
        elif node.is_call_back_table_node or node.is_tagged_app_node:
            self._nodes[node.name] = node
        # In some binaries, we may first see a stub for a user function
        # (represented as a library node) and then see the user function itself.
        elif (
                node.is_app_node
                and node.name in self._nodes
                and self._nodes[node.name].is_lib_node):
            self._nodes[node.name] = node
        else:
            pass

    def node_id_in(self, node: CallgraphNode, where: Iterable[str]) -> bool:
        """Checks if the ids for the passed node are in the passed iterable"""
        return any((node_id in where for node_id in node.ids()))

    def node_in(self, node: CallgraphNode, where: Iterable[CallgraphNode]) -> bool:
        """Checks if the passed node is in the passed iterable"""
        for w_node in where:
            if self.node_id_in(node, w_node.ids()):
                return True
        return False

    def has_node(self, node: CallgraphNode) -> bool:
        return self.node_in(node, self.nodes.values())

    def get_node(self, node_id: str) -> Optional[CallgraphNode]:
        """Returns the node where one of its ids matches node_id"""
        # Cheap check
        if node_id in self._nodes.keys():
            return self._nodes[node_id]

        for node in self._nodes.values():
            if node_id in node.ids():
                return node

        return None

    def add_edge(self, src: CallgraphNode, dst: CallgraphNode) -> None:
        self.add_node(src)
        self.add_node(dst)
        self._edges.setdefault(src.name, {})
        if not self.node_id_in(dst, self._edges[src.name]):
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
            return self.node_id_in(node, sources)

        for n in self.nodes.values():
            if is_source(n):
                result.add_node(n)

        edgesadded: bool = False
        for (src, dsts) in self.edges.items():
            for dst in dsts:
                if (
                        src in self.nodes
                        and result.has_node(self.nodes[src])
                        and not result.has_edge(src, dst)):
                    result.add_edge(self.nodes[src], self.nodes[dst])
                    edgesadded = True

        while edgesadded:
            edgesadded = False
            for (src, dsts) in self.edges.items():
                if src in self.nodes and not result.has_node(self.nodes[src]):
                    continue
                for dst in dsts:
                    if not result.has_edge(src, dst):
                        if src in self.nodes:
                            result.add_edge(self.nodes[src], self.nodes[dst])
                            edgesadded = True
        return result

    def constrain_sinks(self, sinks: List[str]) -> "Callgraph":
        return self.clone(reverse=True).constrain_sources(sinks).clone(
            reverse=True)

    def constrain_sink_edge(self, src: str, dst: str) -> "Callgraph":
        """Constrains the callgraph to those paths that end with the passed edge"""
        # XXX: Add a check that we do have an edge between those two nodes, Otherwise
        # raise an error

        # If we don't have the nodes in the edge then just return an empty
        # callgraph
        src_node = self.get_node(src)
        if not src_node:
            # This can happen if we haven't fully resolved the callgraph
            return Callgraph()
        dst_node = self.get_node(dst)
        if not dst_node:
            # This can happen if we haven't fully resolved the callgraph
            return Callgraph()

        result = self.constrain_sinks([src])
        result_src_node = result.get_node(src)
        # Paranoia check, this shouldn't happen
        if not result_src_node:
            raise UF.CHBError("Constraining failed unexpectedly")

        result.add_edge(src_node, dst_node)
        return result

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["nodes"] = jnodes = []
        content["edges"] = jedges = []
        for node in self.nodes.values():
            jnode = node.to_json_result()
            if jnode.is_ok:
                jnodes.append(jnode.content)
            else:
                return JSONResult("callgraph", {}, "fail", jnode.reason)
        for tgt in self.edges.values():
            for edge in tgt.values():
                jedge = edge.to_json_result()
                if jedge.is_ok:
                    jedges.append(jedge.content)
                else:
                    return JSONResult("callgraph", {}, "fail", jedge.reason)
        return JSONResult("callgraph", content, "ok")

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Number of nodes: " + str(self.nodecount))
        lines.append("Number of edges: " + str(self.edgecount))
        return "\n".join(lines)


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
    elif tgt.is_inlined_app_target:
        tgt = cast(InlinedAppTarget, tgt)
        fname = tgt.name
        return InlinedAppCallgraphNode(str(tgt.address), fname)
    else:
        raise UF.CHBNotImplementedError(
            "Callgraph", "mk_tgt_callgraph_node", str(tgt))


def mk_app_callgraph_node(addr: str, fname: Optional[str]) -> CallgraphNode:
    return AppCallgraphNode(addr, fname)


def mk_tagged_app_callgraph_node(
        tag: str, addr: str, fname: Optional[str] = None) -> CallgraphNode:
    return TaggedAppCallgraphNode(tag, addr, fname)


def mk_call_back_node(tgt: CallTarget) -> CallgraphNode:
    if tgt.is_call_back_table:
        tgt = cast(CallbackTableTarget, tgt)
        addr = tgt.address
        offset = tgt.offset
        return CallbackTableCallgraphNode(addr, offset)
    else:
        raise UF.CHBNotImplementedError(
            "Callgraph", "mk_call_back_callgraph_node", str(tgt))
