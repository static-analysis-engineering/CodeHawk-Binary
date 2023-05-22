# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs LLC
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

import xml.etree.ElementTree as ET

from typing import Any, Callable, Dict, List, Mapping, Sequence, TYPE_CHECKING

from chb.app.BasicBlock import BasicBlock

from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF

from chb.arm.ARMDictionary import ARMDictionary
from chb.arm.ARMInstruction import ARMInstruction

from chb.invariants.XXpr import XXpr

if TYPE_CHECKING:
    from chb.arm.ARMFunction import ARMFunction


class ARMBlock(BasicBlock):

    def __init__(self, armf: "ARMFunction", xnode: ET.Element) -> None:
        BasicBlock.__init__(self, xnode)
        self._armf = armf
        self._instructions: Dict[str, ARMInstruction] = {}

    @property
    def armfunction(self) -> "ARMFunction":
        return self._armf

    @property
    def armdictionary(self) -> ARMDictionary:
        return self.armfunction.armdictionary

    @property
    def instructions(self) -> Mapping[str, ARMInstruction]:
        if len(self._instructions) == 0:
            for n in self.xnode.findall("i"):
                iaddr = n.get("ia")
                if iaddr is None:
                    raise UF.CHBError("ARM Instruction without address in xml")
                self._instructions[iaddr] = ARMInstruction(self, n)
        return self._instructions

    def to_string(
            self,
            bytes: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 40,
            sp: bool = True) -> str:
        lines: List[str] = []
        for (ia, instr) in sorted(self.instructions.items()):
            pinstr = instr.to_string(
                bytes=bytes,
                opcodetxt=opcodetxt,
                opcodewidth=opcodewidth,
                sp=sp)
            lines.append(str(ia).rjust(10) + "  " + pinstr)
        return "\n".join(lines)

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["startaddr"] = self.baddr
        content["endaddr"] = self.lastaddr
        content["instructions"] = instrs = []
        for (iaddr, instr) in self.instructions.items():
            iresult = instr.to_json_result()
            if not iresult.is_ok:
                reason = (
                    "failure at " + iaddr + ": " + str(iresult.reason))
                return JSONResult("assemblyblock", {}, "fail", reason)
            else:
                instrs.append(iresult.content)
        return JSONResult("assemblyblock", content, "ok")
