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
from chb.jsoninterface.JSONControlFlowGraph import JSONControlFlowGraph
from chb.jsoninterface.JSONFunctionComparison import JSONFunctionComparison
from chb.jsoninterface.JSONObject import JSONObject

if TYPE_CHECKING:
    from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor


class JSONCfgBlockMappingItem(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "cfgblockmappingitem")
        self._blocks2: Optional[List[Tuple[str, str]]] = None

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    @property
    def matches(self) -> List[str]:
        return self.d.get("matches", [])

    @property
    def cfg1_block_addr(self) -> str:
        return self.d.get("cfg1-block-addr", self.property_missing("cfg1-block-addr"))

    @property
    def cfg2_blocks(self) -> List[Tuple[str, str]]:
        if self._blocks2 is None:
            result: List[Tuple[str, str]] = []
            for b in self.d.get("cfg2-blocks", []):
                result.append((
                    b.get("cfg2-block-addr", self.property_missing("cfg2-block-addr")),
                    b.get("role")))
            self._blocks2 = result
        return self._blocks2

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_cfg_block_mapping_item(self)


class JSONCfgComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "cfgcomparison")
        self._cfg1: Optional[JSONControlFlowGraph] = None
        self._cfg2: Optional[JSONControlFlowGraph] = None
        self._mapping: Optional[List[JSONCfgBlockMappingItem]] = None

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    @property
    def cfg1(self) -> JSONControlFlowGraph:
        if self._cfg1 is None:
            self._cfg1 = JSONControlFlowGraph(self.d.get("cfg1", {}))
        return self._cfg1

    @property
    def cfg2(self) -> JSONControlFlowGraph:
        if self._cfg2 is None:
            self._cfg2 = JSONControlFlowGraph(self.d.get("cfg2", {}))
        return self._cfg2

    @property
    def cfg_block_mapping(self) -> List[JSONCfgBlockMappingItem]:
        if self._mapping is None:
            result: List[JSONCfgBlockMappingItem] = []
            for m in self.d.get("cfg-block-mapping", []):
                result.append(JSONCfgBlockMappingItem(m))
            self._mapping = result
        return self._mapping

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_cfg_comparison(self)


class JSONCfgComparisons(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "cfgcomparisons")
        self._functions: Optional[List[JSONCfgComparison]] = None

    @property
    def functions_changed(self) -> List[JSONCfgComparison]:
        if self._functions is None:
            result: List[JSONCfgComparison] = []
            for c in self.d.get("functions-changed", []):
                result.append(JSONCfgComparison(c))
            self._functions = result
        return self._functions

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_cfg_comparisons(self)
                              
