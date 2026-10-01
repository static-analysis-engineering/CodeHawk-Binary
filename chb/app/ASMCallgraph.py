# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2026  Aarno Labs LLC
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

import xml.etree.ElementTree as ET

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from chb.jsoninterface.JSONResult import JSONResult


@dataclass
class ASMCallgraphEdge:
    srcfn: str
    callsite: str
    kind: str
    target: str

    def to_json_result(self) -> JSONResult:
        content: Dict[str, str] = {}
        content["srcfn"] = self.srcfn
        content["callsite"] = self.callsite
        content["kind"] = self.kind
        content["target"] = self.target
        return JSONResult("asm-callgraph-edge", content, "ok")


class ASMCallgraph:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode
        self._edges: List[ASMCallgraphEdge] = []
        self._initialize()

    @property
    def edges(self) -> List[ASMCallgraphEdge]:
        return self._edges

    def srcfn_callees(self, src: str) -> List[ASMCallgraphEdge]:
        return [e for e in self.edges if e.srcfn == src]

    def target_callers(self, tgt: str) -> List[ASMCallgraphEdge]:
        return [e for e in self.edges if e.target == tgt]

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["edges"] = edges = []
        for e in self.edges:
            eresult = e.to_json_result().content
            edges.append(eresult)
        return JSONResult("asm-callgraph", content, "ok")

    def _initialize(self) -> None:
        xedges = self.xnode.find("edges")
        if xedges is not None:
            for xedge in xedges.findall("edge"):
                srcfn = xedge.get("src", "?")
                callsite = xedge.get("cs", "?")
                xtgt = xedge.find("tgt")
                if xtgt is not None:
                    kind = xtgt.get("kd", "?")
                    if kind == "app":
                        tgt = xtgt.get("a", "?")
                    elif kind == "so":
                        tgt = xtgt.get("fn", "?")
                    elif kind == "unr":
                        tgt = "unknown"
                    else:
                        tgt = "kind not known: " + kind
                    edge = ASMCallgraphEdge(srcfn, callsite, kind, tgt)
                    self._edges.append(edge)
