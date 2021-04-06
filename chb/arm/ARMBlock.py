# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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

from typing import Callable, Dict, List, TYPE_CHECKING

import chb.util.fileutil as UF

from chb.arm.ARMInstruction import ARMInstruction

if TYPE_CHECKING:
    import chb.arm.ARMFunction


class ARMBlock:

    def __init__(
            self,
            armf: "chb.arm.ARMFunction.ARMFunction",
            xnode: ET.Element) -> None:
        self.armfunction = armf
        self.xnode = xnode
        self.instructions: Dict[str, ARMInstruction] = {}
        self._get_instructions()

    @property
    def baddr(self) -> str:
        baddr = self.xnode.get("ba")
        if baddr is None:
            raise UF.CHBError("Arm block address is missing from xml")
        return baddr

    def has_instruction(self, iaddr: str) -> bool:
        return iaddr in self.instructions

    def get_instruction(self, iaddr: str) -> ARMInstruction:
        if iaddr in self.instructions:
            return self.instructions[iaddr]
        raise UF.CHBError("ARM instruction not found: " + iaddr)

    def iter_instructions(self, f: Callable[[str, ARMInstruction], None]) -> None:
        for iaddr in sorted(self.instructions):
            f(iaddr, self.instructions[iaddr])

    def to_string(self,
                  sp: bool = False,
                  opcodetxt: bool = True,
                  opcodewidth: int = 40) -> str:
        lines: List[str] = []
        for iaddr in sorted(self.instructions):
            pinstr = self.instructions[iaddr].to_string(
                sp=sp,
                opcodetxt=opcodetxt,
                opcodewidth=opcodewidth)
            lines.append(str(iaddr).rjust(10) + "  " + pinstr)
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.to_string()

    def _get_instructions(self) -> None:
        if len(self.instructions) > 0:
            return
        for n in self.xnode.findall("i"):
            iaddr = n.get("ia")
            if not iaddr:
                raise UF.CHBError(
                    "ARM instruction encountered without address in function: "
                    + self.armfunction.faddr)
            self.instructions[iaddr] = ARMInstruction(self, n)
