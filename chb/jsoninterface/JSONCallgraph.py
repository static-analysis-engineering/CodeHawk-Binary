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

from typing import Any, Dict, List, Optional, TYPE_CHECKING


from chb.jsoninterface.JSONObject import JSONObject

if TYPE_CHECKING:
    from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor


class JSONCallgraphEdge(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "callgraphedge")

    @property
    def src(self) -> str:
        return self.d.get("src", self.property_missing("src"))

    @property
    def tgt(self) -> str:
        return self.d.get("tgt", self.property_missing("tgt"))

    @property
    def type(self) -> Optional[str]:
        return self.d.get("type")

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_callgraph_edge(self)


class JSONCallgraphNode(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "callgraphnode")

    @property
    def name(self) -> str:
        return self.d.get("name", self.property_missing("name"))

    @property
    def label(self) -> str:
        return self.d.get("label", self.name)

    @property
    def type(self) -> Optional[str]:
        return self.d.get("type")

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_callgraph_node(self)


class JSONCallgraph(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "callgraph")

    @property
    def nodes(self) -> List[JSONCallgraphNode]:
        return self.d.get("nodes", [])

    @property
    def edges(self) -> List[JSONCallgraphEdge]:
        return self.d.get("edges", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_callgraph(self)


                          

    
                        

