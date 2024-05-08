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

from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from chb.jsoninterface.JSONBlockComparison import JSONBlockComparison
from chb.jsoninterface.JSONControlFlowGraph import JSONControlFlowGraph
from chb.jsoninterface.JSONObject import JSONObject

if TYPE_CHECKING:
    from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor


class JSONCfgBlockMappingItem(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "cfgblockmappingitem")
        self._blocks2: Optional[List[Tuple[str, str]]] = None
        self._blockcomparison: Optional[JSONBlockComparison] = None

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
    def instr_count1(self) -> int:
        return self.d.get("instr-count1", self.property_missing("instr-count1"))

    @property
    def instr_count2(self) -> int:
        return self.d.get("instr-count2", self.property_missing("instr-count2"))

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

    @property
    def block_comparison(self) -> Optional[JSONBlockComparison]:
        # If nothing changed in this block, then this will not be part of the json
        if 'blockcomparison' not in self.d:
            return None

        if self._blockcomparison is None:
            self._block_comparison = JSONBlockComparison(
                self.d.get('blockcomparison', self.property_missing('blockcomparison')))
        return self._block_comparison

    def has_trampoline(self) -> bool:
        return 'blockcount' in self.changes

    def trampoline_address(self) -> Optional[str]:
        if not self.has_trampoline():
            return None

        for (b_addr, role) in self.cfg2_blocks:
            if role == "setupblock":
                return b_addr

        else:
            # the TrampolinePairMinimal2and3 patch has just one block: payload
            # (which is called wrapper in the patch results file)
            for (b_addr, role) in self.cfg2_blocks:
                if role == "payload":
                    return b_addr

        return None

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_cfg_block_mapping_item(self)


class JSONFunctionComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "functioncomparison")
        self._cfg1: Optional[JSONControlFlowGraph] = None
        self._cfg2: Optional[JSONControlFlowGraph] = None
        self._mapping: Optional[List[JSONCfgBlockMappingItem]] = None
        self._blocks_changed: Optional[List[str]] = None

    @property
    def faddr1(self) -> str:
        return self.d.get("faddr1", self.property_missing("faddr1"))

    @property
    def faddr2(self) -> str:
        return self.d.get("faddr2", self.property_missing("faddr2"))

    @property
    def name1(self) -> Optional[str]:
        return self.d.get("name1")

    @property
    def name2(self) -> Optional[str]:
        return self.d.get("name2")

    @property
    def display_name(self) -> str:
        if self.name1:
            return self.name1
        else:
            return self.faddr1

    @property
    def cfg1(self) -> JSONControlFlowGraph:
        if self._cfg1 is None:
            self._cfg1 = JSONControlFlowGraph(
                self.d.get("cfg1", self.property_missing("cfg1")))
        return self._cfg1

    @property
    def cfg2(self) -> JSONControlFlowGraph:
        if self._cfg2 is None:
            self._cfg2 = JSONControlFlowGraph(
                self.d.get("cfg2", self.property_missing("cfg2")))
        return self._cfg2

    @property
    def num_blocks1(self) -> int:
        return len(self.cfg1.nodes)

    @property
    def num_blocks2(self) -> int:
        return len(self.cfg2.nodes)

    @property
    def blocks_changed(self) -> List[str]:
        if self._blocks_changed is None:
            self._blocks_changed = self.d["blocks-changed"]

        return self._blocks_changed

    @property
    def num_blocks_changed(self) -> int:
        return len(self.blocks_changed)

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", self.property_missing("changes"))

    @property
    def cfg_block_mapping(self) -> List[JSONCfgBlockMappingItem]:
        if self._mapping is None:
            result: List[JSONCfgBlockMappingItem] = []
            for m in self.d.get("cfg-block-mapping", []):
                result.append(JSONCfgBlockMappingItem(m))
            self._mapping = result
        return self._mapping

    @property
    def matches(self) -> List[str]:
        return self.d.get("matches", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_function_comparison(self)
