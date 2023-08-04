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

from typing import Any, Dict, List, Optional, TYPE_CHECKING, Union

from chb.jsoninterface.JSONInstructionComparison import (
    JSONInstructionComparison)
from chb.jsoninterface.JSONObject import JSONObject


if TYPE_CHECKING:
    from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor


class JSONBlockSemanticComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "blocksemanticcomparison")

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_block_semantic_comparison(self)


class JSONBlockComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "blockcomparison")

        # instruction edits (string-like transformations)
        self._instructioninsertions: Optional[List[str]] = None
        self._instructiondeletions: Optional[List[str]] = None
        self._instructionsubstitutions: (
            Optional[List[JSONInstructionComparison]]) = None

        # whole-block semantic comparison
        self._semanticcomparison: Optional[JSONBlockSemanticComparison] = None

    @property
    def baddr1(self) -> str:
        return self.d.get("baddr1", self.property_missing("baddr1"))

    @property
    def baddr2(self) -> str:
        return self.d.get("baddr2", self.property_missing("baddr2"))

    @property
    def lev_distance(self) -> int:
        return self.d.get("lev-distance", -1)

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    @property
    def matches(self) -> List[str]:
        return self.d.get("matches", [])

    @property
    def semantic_comparison(self) -> JSONBlockSemanticComparison:
        if self._semanticcomparison is None:
            self._semanticcomparison = JSONBlockSemanticComparison(
                self.d.get("semantic-comparison", {}))
        return self._semanticcomparison

    @property
    def instruction_insertions(self) -> List[str]:
        if self._instructioninsertions is None:
            self._instructioninsertions = []
            for i in self.d.get("instruction-insertions", []):
                self._instructioninsertions.append(i)
        return self._instructioninsertions

    @property
    def instruction_deletions(self) -> List[str]:
        if self._instructiondeletions is None:
            self._instructiondeletions = []
            for i in self.d.get("instruction-deletions", []):
                self._instructiondeletions.append(i)
        return self._instructiondeletions

    @property
    def instruction_substitutions(self) -> List[JSONInstructionComparison]:
        if self._instructionsubstitutions is None:
            self._instructionsubstitutions = []
            for i in self.d.get("instruction-substitutions", []):
                self._instructionsubstitutions.append(
                    JSONInstructionComparison(i))
        return self._instructionsubstitutions

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_block_comparison(self)


class JSONXEdgeDetail(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "xedgedetail")

    @property
    def src(self) -> str:
        return self.d.get("src", self.property_missing("src"))

    @property
    def tgt(self) -> str:
        return self.d.get("tgt", self.property_missing("tgt"))

    @property
    def role(self) -> str:
        return self.d.get("role", self.property_missing("role"))

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_xedge_detail(self)


class JSONXBlockDetail(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "xblockdetail")

    @property
    def baddr(self) -> str:
        return self.d.get("baddr", self.property_missing("baddr"))

    @property
    def role(self) -> str:
        return self.d.get("role", self.property_missing("role"))

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_xblock_detail(self)


class JSONBlockExpansion(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "blockexpansion")
        self._xblocks: Optional[List[JSONXBlockDetail]] = None
        self._xedges: Optional[List[JSONXEdgeDetail]] = None

    @property
    def kind(self) -> str:
        return self.d.get("kind", self.property_missing("kind"))

    @property
    def xblocks(self) -> List[JSONXBlockDetail]:
        if self._xblocks is None:
            self._xblocks = []
            for x in self.d.get("xblocks", []):
                self._xblocks.append(JSONXBlockDetail(x))
        return self._xblocks

    @property
    def xedges(self) -> List[JSONXEdgeDetail]:
        if self._xedges is None:
            self._xedges = []
            for x in self.d.get("xedges", []):
                self._xedges.append(JSONXEdgeDetail(x))
        return self._xedges

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_block_expansion(self)
