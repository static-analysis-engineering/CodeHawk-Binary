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

from chb.jsoninterface.JSONBlockComparison import JSONBlockComparison
from chb.jsoninterface.JSONObject import JSONObject

if TYPE_CHECKING:
    from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor


class JSONFunctionComparisonDetails(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "function-comparison-details")
        self._block_comparisons: Optional[List[JSONBlockComparison]] = None

    @property
    def block_comparisons(self) -> List[JSONBlockComparison]:
        if self._block_comparisons is None:
            result: List[JSONBlockComparison] = []
            for b in self.d.get("block-comparisons", []):
                result.append(JSONBlockComparison(b))
            self._block_comparisons = result
        return self._block_comparisons

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_function_comparison_details(self)


class JSONFunctionVariablesComparisonSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "variables-summary")

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_function_variables_comparison_summary(self)


class JSONCfgComparisonSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "cfg-summary")

    @property
    def cfg_mapping(self) -> str:
        return self.d.get("cfg-mapping", self.property_missing("cfg-mapping"))

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_cfg_comparison_summary(self)


class JSONFunctionBlockMappedSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "function-block-mapped")

    @property
    def baddr(self) -> str:
        return self.d.get("baddr", self.property_missing("baddr"))

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
        visitor.visit_function_block_mapped_summary(self)

                          

class JSONFunctionBlocksComparisonSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "function-blocks-comparison-summary")
        self._blocks_mapped: Optional[List[JSONFunctionBlockMappedSummary]] = None

    @property
    def function_blocks_mapped(self) -> List[JSONFunctionBlockMappedSummary]:
        if self._blocks_mapped is None:
            result: List[JSONFunctionBlockMappedSummary] = []
            for b in self.d.get("function-blocks-mapped", []):
                result.append(JSONFunctionBlockMappedSummary(b))
            self._blocks_mapped = result
        return self._blocks_mapped

    @property
    def function_blocks_added(self) -> List[str]:
        return self.d.get("function-blocks-added", [])

    @property
    def function_blocks_removed(self) -> List[str]:
        return self.d.get("function-blocks-removed", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_function_blocks_comparison_summary(self)
                         


class JSONFunctionComparisonSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "function-comparison-summary")
        self._blocks_summary: Optional[JSONFunctionBlocksComparisonSummary] = None
        self._variables_summary: Optional[JSONFunctionVariablesComparisonSummary] = None
        self._cfg_summary: Optional[JSONCfgComparisonSummary] = None

    @property
    def function_blocks_comparison_summary(
            self) -> JSONFunctionBlocksComparisonSummary:
        if self._blocks_summary is None:
            self._blocks_summary = JSONFunctionBlocksComparisonSummary(
                self.d.get("function-blocks-comparison-summary", {}))
        return self._blocks_summary

    @property
    def function_variables_comparison_summary(
            self) -> JSONFunctionVariablesComparisonSummary:
        if self._variables_summary is None:
            self._variables_summary = JSONFunctionVariablesComparisonSummary(
                self.d.get("function-variables-comparison-summary", {}))
        return self._variables_summary

    @property
    def cfg_comparison_summary(self) -> JSONCfgComparisonSummary:
        if self._cfg_summary is None:
            self._cfg_summary = JSONCfgComparisonSummary(
                self.d.get("cfg-comparison-summary", {}))
        return self._cfg_summary

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_function_comparison_summary(self)


class JSONFunctionComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "functioncomparison")
        self._summary: Optional[JSONFunctionComparisonSummary] = None
        self._details: Optional[JSONFunctionComparisonDetails] = None

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
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    @property
    def matches(self) -> List[str]:
        return self.d.get("matches", [])

    @property
    def function_comparison_summary(self) -> JSONFunctionComparisonSummary:
        if self._summary is None:
            self._summary = JSONFunctionComparisonSummary(
                self.d.get("function-comparison-summary", {}))
        return self._summary

    @property
    def function_comparison_details(self) -> JSONFunctionComparisonDetails:
        if self._details is None:
            self._details = JSONFunctionComparisonDetails(
                self.d.get("function-comparison-details", {}))
        return self._details

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_function_comparison(self)
                     
