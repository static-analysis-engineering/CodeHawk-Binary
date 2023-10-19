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


from chb.jsoninterface.JSONObject import JSONObject

if TYPE_CHECKING:
    from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor


class JSONCallsiteTgtParameter(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "callsitetgtparameter")

    @property
    def name(self) -> str:
        return self.d.get("name", self.property_missing("name"))

    @property
    def roles(self) -> List[str]:
        return self.d.get("roles", [])

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_callsite_tgt_parameter(self)


class JSONCallsiteTgtFunction(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "callsitetgtfunction")
        self._parameters: Optional[List[JSONCallsiteTgtParameter]] = None

    @property
    def name(self) -> str:
        return self.d.get("name", self.property_missing("name"))

    @property
    def parameters(self) -> List[JSONCallsiteTgtParameter]:
        if self._parameters is None:
            result: List[JSONCallsiteTgtParameter] = []
            for param in self.d.get("parameters", []):
                result.append(JSONCallsiteTgtParameter(param))
            self._parameters = result
        return self._parameters

    @property
    def varargs(self) -> bool:
        return self.d.get("varargs", False)

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_callsite_tgt_function(self)


class JSONCallsiteArgument(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "callsiteargument")
        self._roles: Optional[List[Tuple[str, str]]] = None

    @property
    def name(self) -> str:
        return self.d.get("name", self.property_missing("name"))

    @property
    def value(self) -> str:
        return self.d.get("value", self.property_missing("value"))

    @property
    def roles(self) -> List[Tuple[str, str]]:
        if self._roles is None:
            result: List[Tuple[str, str]] = []
            for role in self.d.get("roles", []):
                rolename = role.get("rn", self.property_missing("roles:rn"))
                rolevalue = role.get("rv", self.property_missing("roles:rv"))
                result.append((rolename, rolevalue))
            self._roles = result
        return self._roles

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_callsite_argument(self)


class JSONCallsiteRecord(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "callsiterecord")
        self._arguments: Optional[List[JSONCallsiteArgument]] = None

    @property
    def faddr(self) -> str:
        return self.d.get("faddr", self.property_missing("faddr"))

    @property
    def iaddr(self) -> str:
        return self.d.get("iaddr", self.property_missing("iaddr"))

    @property
    def arguments(self) -> List[JSONCallsiteArgument]:
        if self._arguments is None:
            result: List[JSONCallsiteArgument] = []
            for arg in self.d.get("arguments", []):
                result.append(JSONCallsiteArgument(arg))
            self._arguments = result
        return self._arguments

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_callsite_record(self)


class JSONCallsiteRecords(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "callsiterecords")
        self._function_names: Optional[Dict[str, str]] = None
        self._tgtfunction: Optional[JSONCallsiteTgtFunction] = None
        self._callsites: Optional[List[JSONCallsiteRecord]] = None

    @property
    def function_names(self) -> Dict[str, str]:
        if self._function_names is None:
            result: Dict[str, str] = {}
            for fn in self.d.get("function-names", []):
                fnaddr = fn.get("addr", self.property_missing("function-names:addr"))
                fnname = fn.get("name", self.property_missing("function-names:name"))
                if fnaddr in result:
                    if result[fnaddr] != fnname:
                        raise Exception(
                            "Address cannot be associated with multiple names: "
                            + fnaddr
                            + ": ["
                            + result[fnaddr]
                            + ", "
                            + fnname
                            + "]")
                    else:
                        pass
                else:
                    result[fnaddr] = fnname
            self._function_names = result
        return result

    @property
    def cgpath_src(self) -> Optional[str]:
        return self.d.get("cgpath-src")

    @property
    def tgt_function(self) -> JSONCallsiteTgtFunction:
        if self._tgtfunction is None:
            tgtfn = self.d.get("tgt-function", {})
            self._tgtfunction = JSONCallsiteTgtFunction(tgtfn)
        return self._tgtfunction

    @property
    def callsites(self) -> List[JSONCallsiteRecord]:
        if self._callsites is None:
            result: List[JSONCallsiteRecord] = []
            for csrec in self.d.get("callsites", []):
                result.append(JSONCallsiteRecord(csrec))
            self._callsites = result
        return self._callsites

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_callsite_records(self)
    

                              
