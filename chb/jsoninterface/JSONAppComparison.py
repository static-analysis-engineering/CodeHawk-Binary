# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2024  Aarno Labs LLC
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


class JSONCallgraphComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "callgraph-comparison")

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_callgraph_comparison(self)


class JSONBinaryComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "binary-comparison")

    @property
    def changes(self) -> List[str]:
        return self.d.get("changes", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_binary_comparison(self)


class JSONGlobalVarComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "globalvar-comparison")

    @property
    def gaddr(self) -> str:
        return self.d.get("gaddr1", self.property_missing("gaddr1"))

    @property
    def name(self) -> Optional[str]:
        return self.d.get("name")

    @property
    def moved_to(self) -> Optional[str]:
        return self.d.get("moved-to")

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_globalvar_comparison(self)


class JSONFunctionAdded(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "functionadded")

    @property
    def faddr(self) -> str:
        return self.d.get("faddr", self.property_missing("faddr"))

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_function_added(self)


class JSONFunctionMD5(JSONObject):
    """Function address with md5 of syntactic assembly representation string."""

    def __init__(self, d: Dict[str, str]) -> None:
        JSONObject.__init__(self, d, "functionmd5")

    @property
    def faddr(self) -> str:
        return self.d.get("faddr", self.property_missing("faddr"))

    @property
    def md5(self) -> str:
        return self.d.get("md5", self.property_missing("md5"))

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_function_md5(self)


class JSONAppMD5Comparison(JSONObject):
    """Raw listing of the functions constructed in the two binaries.

    This object presents two lists of function, md5 pairs that lets a client tool
    confirm which functions have syntactically changed in the binary."""

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "functions-constructed")

    @property
    def file1(self) -> List[JSONFunctionMD5]:
        return self.d.get("file1", self.property_missing("file1"))

    @property
    def file2(self) -> List[JSONFunctionMD5]:
        return self.d.get("file2", self.property_missing("file2"))

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_app_md5_comparison(self)


class JSONAppComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "appcomparison")
        self._xfile1: Optional[AX.XFilePath] = None
        self._xfile2: Optional[AX.XFilePath] = None
        self._functionscompared: Optional[List[str]] = None
        self._functionschanged: Optional[List[JSONFunctionComparison]] = None
        self._functionsadded: Optional[List[JSONFunctionAdded]] = None
        self._functionsremoved: Optional[List[str]] = None
        self._callgraphcomparison: Optional[JSONCallgraphComparison] = None
        self._globalvarscompared: Optional[List[str]] = None
        self._globalvarschanged: Optional[List[JSONGlobalVarComparison]] = None
        self._binarycomparison: Optional[JSONBinaryComparison] = None
        self._appmd5comparison: Optional[JSONAppMD5Comparison] = None

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
    def functions_compared(self) -> List[str]:
        if self._functionscompared is None:
            self._functionscompared = []
            for faddr in self.d.get("functions-compared", []):
                self._functionscompared.append(faddr)
        return self._functionscompared

    @property
    def functions_changed(self) -> List[JSONFunctionComparison]:
        if self._functionschanged is None:
            self._functionschanged = []
            for f in self.d.get("functions-changed", []):
                self._functionschanged.append(JSONFunctionComparison(f))
        return self._functionschanged

    @property
    def functions_added(self) -> List[JSONFunctionAdded]:
        if self._functionsadded is None:
            self._functionsadded = []
            for f in self.d.get("functions-added", []):
                self._functionsadded.append(JSONFunctionAdded(f))
        return self._functionsadded

    @property
    def functions_removed(self) -> List[str]:
        if self._functionsremoved is None:
            self._functionsremoved = []
            for faddr in self.d.get("functions-removed", []):
                self._functionsremoved.append(faddr)
        return self._functionsremoved

    @property
    def callgraph_comparison(self) -> JSONCallgraphComparison:
        if self._callgraphcomparison is None:
            cg = self.d.get("callgraph-comparison", {})
            self._callgraphcomparison = JSONCallgraphComparison(cg)
        return self._callgraphcomparison

    @property
    def globalvars_compared(self) -> List[str]:
        if self._globalvarscompared is None:
            self._globalvarscompared = []
            for gaddr in self.d.get("globalvars-compared", []):
                self._globalvarscompared.append(gaddr)
        return self._globalvarscompared

    @property
    def globalvars_changed(self) -> List[JSONGlobalVarComparison]:
        if self._globalvarschanged is None:
            self._globalvarschanged = []
            for gv in self.d.get("globalvars-changed", []):
                self._globalvarschanged.append(JSONGlobalVarComparison(gv))
        return self._globalvarschanged

    @property
    def binary_comparison(self) -> JSONBinaryComparison:
        if self._binarycomparison is None:
            self._binarycomparison = JSONBinaryComparison(self.d.get("binary-comparison", {}))
        return self._binarycomparison

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_app_comparison(self)
