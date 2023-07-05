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

from chb.jsoninterface.JSONAssemblyInstruction import JSONAssemblyInstruction
from chb.jsoninterface.JSONObject import JSONObject

if TYPE_CHECKING:
    from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor


class JSONInstructionAddedInfo(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "instruction-added-info")

    @property
    def iaddr(self) -> str:
        return self.d.get("iaddr", self.property_missing("iaddr"))

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_instruction_added_info(self)


class JSONInstructionRemovedInfo(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "instruction-removed-info")

    @property
    def iaddr(self) -> str:
        return self.d.get("iaddr", self.property_missing("iaddr"))

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_instruction_removed_info(self)

                          
class JSONInstructionComparison(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "instruction-comparison")
        self._instr1: Optional[JSONAssemblyInstruction] = None
        self._instr2: Optional[JSONAssemblyInstruction] = None

    @property
    def iaddr1(self) -> str:
        return self.d.get("iaddr1", self.property_missing("iaddr1"))

    @property
    def iaddr2(self) -> str:
        return self.d.get("iaddr2", self.property_missing("iaddr2"))

    @property
    def instr1(self) -> JSONAssemblyInstruction:
        if self._instr1 is None:
            self._instr1 = JSONAssemblyInstruction(self.d.get("instr1", {}))
        return self._instr1

    @property
    def instr2(self) -> JSONAssemblyInstruction:
        if self._instr2 is None:
            self._instr2 = JSONAssemblyInstruction(self.d.get("instr2", {}))
        return self._instr2

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_instruction_comparison(self)

                          
                                                   
