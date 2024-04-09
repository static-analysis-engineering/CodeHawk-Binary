# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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

from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING, Union

import chb.jsoninterface.AuxiliaryClasses as AX
from chb.jsoninterface.JSONAssemblyBlock import JSONAssemblyBlock
from chb.jsoninterface.JSONObject import JSONObject

if TYPE_CHECKING:
    from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor


class JSONCfgNode(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "cfgnode")
        self._code: Optional[JSONAssemblyBlock] = None

    @property
    def baddr(self) -> str:
        return self.d.get("baddr", self.property_missing("baddr"))

    @property
    def id(self) -> str:
        """Returns the unique identifier for this cfg node.

        This normally corresponds to BasicBlock.baddr, whereas baddr
        above corresponds to BasicBlock.real_baddr.
        """
        return self.d.get("id", self.property_missing("id"))

    @property
    def code(self) -> JSONAssemblyBlock:
        if self._code is None:
            self._code = JSONAssemblyBlock(self.d.get("code", {}))
        return self._code

    @property
    def nesting_level(self) -> Optional[int]:
        lvl = self.d.get("nesting-level")
        if lvl is not None:
            return int(lvl)
        else:
            return None

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_cfg_node(self)


class JSONCfgEdge(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "cfgedge")

    @property
    def src(self) -> str:
        return self.d.get("src", self.property_missing("src"))

    @property
    def tgt(self) -> str:
        return self.d.get("tgt", self.property_missing("tgt"))

    @property
    def kind(self) -> str:
        return self.d.get("kind", self.property_missing("kind"))

    @property
    def predicate(self) -> Optional[str]:
        if "predicate" in self.d:
            return self.d.get(
                "predicate",
                {"txtrep": "?"}).get("txtrep",
                                     self.property_missing("predicate.txtrep"))
        return None

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_cfg_edge(self)


class JSONControlFlowGraph(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "controlflowgraph")
        self._nodes: Optional[List[JSONCfgNode]] = None
        self._edges: Optional[List[JSONCfgEdge]] = None

    @property
    def name(self) -> Optional[str]:
        return self.d.get("name")

    @property
    def faddr(self) -> str:
        return self.d.get("faddr", self.property_missing("faddr"))

    @property
    def md5hash(self) -> str:
        return self.d.get("md5hash", self.property_missing("md5hash"))

    @property
    def nodes(self) -> List[JSONCfgNode]:
        if self._nodes is None:
            result: List[JSONCfgNode] = []
            for n in self.d.get("nodes", []):
                result.append(JSONCfgNode(n))
            self._nodes = result
        return self._nodes

    @property
    def edges(self) -> List[JSONCfgEdge]:
        if self._edges is None:
            result: List[JSONCfgEdge] = []
            for e in self.d.get("edges", []):
                result.append(JSONCfgEdge(e))
            self._edges = result
        return self._edges

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_control_flow_graph(self)
