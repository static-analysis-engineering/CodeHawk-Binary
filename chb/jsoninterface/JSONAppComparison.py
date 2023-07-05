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

import chb.jsoninterface.AuxiliaryClasses as AX
from chb.jsoninterface.JSONFunctionComparison import JSONFunctionComparison
from chb.jsoninterface.JSONObject import JSONObject

if TYPE_CHECKING:
    from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor


class JSONAppComparisonDetails(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "app-details")
        self._function_comparisons: Optional[List[JSONFunctionComparison]] = None

    @property
    def function_comparisons(self) -> List[JSONFunctionComparison]:
        if self._function_comparisons is None:
            result: List[JSONFunctionComparison] = []
            for c in self.d.get("function-comparisons", []):
                result.append(JSONFunctionComparison(c))
            self._function_comparisons = result
        return self._function_comparisons

    @property
    def function_comparisons_omitted(self) -> List[str]:
        return self.d.get("function-comparisons-omitted", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_app_comparison_details(self)


class JSONGlobalsComparisonSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "globals-comparison-summary")

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_globals_comparison_summary(self)


class JSONCallgraphComparisonSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "callgraph-comparison-summary")

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_callgraph_comaprison_summary(self)


class JSONAppFunctionMappedSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "app-function-mapped-summary")

    @property
    def faddr(self) -> str:
        return self.d.get("faddr", self.property_missing("faddr"))

    @property
    def name(self) -> Optional[str]:
        return self.d.get("name")

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    @property
    def matches(self) -> List[str]:
        return self.d.get("matches", [])

    @property
    def moved_to(self) -> Optional[str]:
        return self.d.get("moved-to")

    @property
    def blocks_changed(self) -> Optional[int]:
        if "blocks-changed" in self.d:
            return int(self.d.get("blocks-changed", 0))
        else:
            return None                       

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_app_function_mapped_summary(self)


class JSONAppFunctionsComparisonSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "functions-comparison-summary")
        self._functions_mapped: Optional[List[JSONAppFunctionMappedSummary]] = None

    @property
    def app_functions_mapped(self) -> List[JSONAppFunctionMappedSummary]:
        if self._functions_mapped is None:
            result: List[JSONAppFunctionMappedSummary] = []
            for f in self.d.get("app-functions-mapped", []):
                result.append(JSONAppFunctionMappedSummary(f))
            self._functions_mapped = result
        return self._functions_mapped

    @property
    def app_functions_added(self) -> List[str]:
        return self.d.get("app-functions-added", [])

    @property
    def app_functions_removed(self) -> List[str]:
        return self.d.get("app-functions-removed", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_app_functions_comparison_summary(self)


class JSONAppComparisonSummary(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "app-comparison-summary")
        self._functions_summary: Optional[JSONAppFunctionsComparisonSummary] = None
        self._globals_summary: Optional[JSONGlobalsComparisonSummary] = None
        self._callgraph_summary: Optional[JSONCallgraphComparisonSummary] = None

    @property
    def functions_summary(self) -> JSONAppFunctionsComparisonSummary:
        if self._functions_summary is None:
            self._functions_summary = JSONAppFunctionsComparisonSummary(
                self.d.get("app-functions-comparison-summary", {}))
        return self._functions_summary

    @property
    def globals_summary(self) -> JSONGlobalsComparisonSummary:
        if self._globals_summary is None:
            self._globals_summary = JSONGlobalsComparisonSummary(
                self.d.get("globals-comparison-summary", {}))
        return self._globals_summary

    @property
    def callgraph_summary(self) -> JSONCallgraphComparisonSummary:
        if self._callgraph_summary is None:
            self._callgraph_summary = JSONCallgraphComparisonSummary(
                self.d.get("callgraph-comparison-summary", {}))
        return self._callgraph_summary

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_app_comparison_summary(self)


class JSONAppComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "appcomparison")
        self._xfile1: Optional[AX.XFilePath] = None
        self._xfile2: Optional[AX.XFilePath] = None
        self._summary: Optional[JSONAppComparisonSummary] = None
        self._details: Optional[JSONAppComparisonDetails] = None

    @property
    def file1(self) -> str:
        if self._xfile1 is None:
            self._xfile1 =  AX.XFilePath(self.d.get("file1", {}))
        return self._xfile1.filepath

    @property
    def file2(self) -> str:
        if self._xfile2 is None:
            self._xfile2 = AX.XFilePath(self.d.get("file2", {}))
        return self._xfile2.filepath

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    @property
    def matches(self) -> List[str]:
        return self.d.get("matches", [])

    @property
    def app_comparison_summary(self) -> JSONAppComparisonSummary:
        if self._summary is None:            
            self._summary = JSONAppComparisonSummary(
                self.d.get("app-comparison-summary", {}))
        return self._summary

    @property
    def app_comparison_details(self) -> JSONAppComparisonDetails:
        if self._details is None:
            self._details = JSONAppComparisonDetails(
                self.d.get("app-comparison-details", {}))
        return self._details

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_app_comparison(self)
