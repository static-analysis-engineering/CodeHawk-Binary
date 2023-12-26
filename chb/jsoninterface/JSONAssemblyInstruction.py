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

from typing import Any, Dict, List, Tuple, Optional, TYPE_CHECKING

from chb.jsoninterface.JSONObject import JSONObject
from chb.jsoninterface.JSONStackpointerOffset import (
    JSONStackpointerOffset, mk_stackpointer_offset)

if TYPE_CHECKING:
    from chb.jsoninterface.JSONObjectVisitor import JSONObjectVisitor



class JSONAssemblyInstruction(JSONObject):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONObject.__init__(self, d, "assemblyinstruction")

    @property
    def addr(self) -> List[str]:
        return self.d.get("addr", self.property_missing("addr"))

    @property
    def stackpointer(self) -> Optional[JSONStackpointerOffset]:
        if "stackpointer" in self.d:
            return JSONStackpointerOffset(self.d.get("stackpointer", {}))
        else:
            return None

    @property
    def bytes(self) -> str:
        return self.d.get("bytes", self.property_missing("bytes"))

    @property
    def opcode(self) -> Tuple[str, str]:
        return self.d.get("opcode", self.property_missing("opcode"))

    @property
    def annotation(self) -> str:
        return self.d.get("annotation", self.property_missing("annotation"))

    def accept(self, visitor: "JSONObjectVisitor") -> None:
        visitor.visit_assembly_instruction(self)
