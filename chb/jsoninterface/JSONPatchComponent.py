# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024  Aarno Labs LLC
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
"""JSON objects related to patch components."""

from typing import Any, Dict, List, Optional, Union, TYPE_CHECKING

from chb.jsoninterface.JSONAssemblyInstruction import JSONAssemblyInstruction
from chb.jsoninterface.JSONObject import JSONObject

if TYPE_CHECKING:
    from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor


class JSONHookInstruction(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "hookinstr")

    @property
    def srca(self) -> str:
        return self.d.get("srca", self.property_missing("srca"))

    @property
    def tgta(self) -> str:
        return self.d.get("tgta", self.property_missing("tgta"))

    @property
    def size(self) -> int:
        return self.d.get("size", self.property_missing("size"))

    @property
    def instr(self) -> JSONAssemblyInstruction:
        return self.d.get("instr", self.property_missing("instr"))

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_hookinstr(self)


class JSONCodeFragment(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "codefragment")
        self._instructions: Optional[List[JSONAssemblyInstruction]] = None

    @property
    def starta(self) -> str:
        return self.d.get("starta", self.property_missing("starta"))

    @property
    def instructions(self) -> List[JSONAssemblyInstruction]:
        if self._instructions is None:
            self._instructions = []
            for instr in self.d.get("instructions", []):
                self._instructions.append(JSONAssemblyInstruction(instr))
        return self._instructions

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_codefragment(self)


class JSONPatchComponent(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "patchcomponent")
        self._component: Optional[
            Union[JSONHookInstruction, JSONCodeFragment]] = None

    @property
    def role(self) -> str:
        return self.d.get("role", self.property_missing("role"))

    @property
    def kind(self) -> str:
        return self.d.get("kind", self.property_missing("role"))

    @property
    def value(self) -> Union[JSONHookInstruction, JSONCodeFragment]:
        if self._component is None:
            if self.kind == "hook":
                self._component = JSONHookInstruction(self.d.get("value", {}))
            else:
                self._component = JSONCodeFragment(self.d.get("value", {}))
        return self._component

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_patch_component(self)
