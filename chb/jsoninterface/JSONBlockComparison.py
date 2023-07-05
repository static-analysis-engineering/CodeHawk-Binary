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
    JSONInstructionAddedInfo,
    JSONInstructionComparison,
    JSONInstructionRemovedInfo)
from chb.jsoninterface.JSONObject import JSONObject

if TYPE_CHECKING:
    from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor


class JSONBlockComparisonDetails(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "block-comparison-details")
        self._instruction_comparisons: Optional[
            List[JSONInstructionComparison]] = None
        self._instructions_added: Optional[List[JSONInstructionAddedInfo]] =  None
        self._instructions_removed: Optional[
            List[JSONInstructionRemovedInfo]] = None

    @property
    def instruction_comparisons(self) -> List[JSONInstructionComparison]:
        if self._instruction_comparisons is None:
            result: List[JSONInstructionComparison] = []
            for i in self.d.get("instruction-comparisons", []):
                result.append(JSONInstructionComparison(i))
            self._instruction_comparisons = result
        return self._instruction_comparisons

    @property
    def instructions_added(self) -> List[JSONInstructionAddedInfo]:
        if self._instructions_added is None:
            result: List[JSONInstructionAddedInfo] = []
            for a in self.d.get("instructions-added", []):
                result.append(JSONInstructionAddedInfo(a))
            self._instructions_added = result                              
        return self._instructions_added

    @property
    def instructions_removed(self) -> List[JSONInstructionRemovedInfo]:
        if self._instructions_removed is None:
            result: List[JSONInstructionRemovedInfo] = []
            for r in self.d.get("instructions-removed", []):
                result.append(JSONInstructionRemovedInfo(r))
            self._instructions_removed = result
        return self._instructions_removed        

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_block_comparison_details(self)


class JSONBlockSemanticsComparisonSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "block-semantics-comparison-summary")

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_block_semantics_comparison_summary(self)


class JSONBlockInstructionMappedSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "block-instruction-mapped-summary")

    @property
    def iaddr(self) -> str:
        return self.d.get("iaddr", self.property_missing("iaddr"))

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    @property
    def matches(self) -> List[str]:
        return self.d.get("matches", [])

    @property
    def moved_to(self) -> Optional[str]:
        return self.d.get("moved-to")

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_block_instruction_mapped_summary(self)


class JSONBlockInstructionsComparisonSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "block-instructions-comparison-summary")
        self._instructions_mapped: Optional[
            List[JSONBlockInstructionMappedSummary]] = None

    @property
    def block_instructions_mapped(self) -> List[JSONBlockInstructionMappedSummary]:
        if self._instructions_mapped is None:
            result: List[JSONBlockInstructionMappedSummary] = []
            for i in self.d.get("block-instructions-mapped", []):
                result.append(JSONBlockInstructionMappedSummary(i))
            self._instructions_mapped = result
        return self._instructions_mapped

    @property
    def block_instructions_added(self) -> List[str]:
        return self.d.get("block-instructions-added", [])

    @property
    def block_instructions_removed(self) -> List[str]:
        return self.d.get("block-instructions-removed", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_block_instructions_comparison_summary(self)


class JSONBlockComparisonSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "block-summary")
        self._instructions_summary: Optional[
            JSONBlockInstructionsComparisonSummary] = None
        self._block_semantics_summary: Optional[
            JSONBlockSemanticsComparisonSummary] = None

    @property
    def block_instructions_comparison_summary(
            self) -> JSONBlockInstructionsComparisonSummary:
        if self._instructions_summary is None:
            self._instructions_summary = JSONBlockInstructionsComparisonSummary(
                self.d.get("block-instructions-comparison-summary", {}))
        return self._instructions_summary

    @property
    def block_semantics_comparison_summary(
            self) -> JSONBlockSemanticsComparisonSummary:
        if self._block_semantics_summary is None:
            self._block_semantics_summary = JSONBlockSemanticsComparisonSummary(
                self.d.get("block-semantics-comparison-summary", {}))
        return self._block_semantics_summary

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_block_comparison_summary(self)


class JSONBlockComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "block-comparison")
        self._summary: Optional[JSONBlockComparisonSummary] = None
        self._details: Optional[JSONBlockComparisonDetails] = None

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
    def block_comparison_summary(self) -> JSONBlockComparisonSummary:
        if self._summary is None:
            self._summary = JSONBlockComparisonSummary(
                self.d.get("block-comparison-summary", {}))
        return self._summary

    @property
    def block_comparison_details(self) -> JSONBlockComparisonDetails:
        if self._details is None:
            self._details = JSONBlockComparisonDetails(
                self.d.get("block-comparison-details", {}))
        return self._details

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_block_comparison(self)
