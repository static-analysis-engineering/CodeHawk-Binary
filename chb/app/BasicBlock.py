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
"""Superclass of a basic block for different architectures.

Subclasses:
 - ARMBlock
 - AsmBlock
 - MIPSBlock
"""

import xml.etree.ElementTree as ET

from typing import Callable, Dict, List, Mapping, Sequence, TYPE_CHECKING

import chb.app.Instruction as I
import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.app.Function


class BasicBlock:

    def __init__(
            self,
            f: "chb.app.Function.Function",
            xnode: ET.Element) -> None:
        self._function = f
        self.xnode = xnode

    @property
    def function(self) -> "chb.app.Function.Function":
        return self._function

    @property
    def baddr(self) -> str:
        _baddr = self.xnode.get("ba")
        if _baddr is None:
            raise UF.CHBError("Basic block address is missing from xml")
        return _baddr

    @property
    def instructions(self) -> Mapping[str, I.Instruction]:
        raise UF.CHBError(
            "Property instructions not implemented for BasicBlock")

    @property
    def call_instructions(self) -> Sequence[I.Instruction]:
        raise UF.CHBError(
            "Property call instruction not implemented for BasicBlock")

    def has_instruction(self, iaddr: str) -> bool:
        return iaddr in self.instructions

    def get_instruction(self, iaddr: str) -> I.Instruction:
        if iaddr in self.instructions:
            return self.instructions[iaddr]
        raise UF.CHBError("Instruction " + iaddr + " not found")

    def iter(self, f: Callable[[str, I.Instruction], None]) -> None:
        for iaddr in sorted(self.instructions):
            f(iaddr, self.instructions[iaddr])

    def to_string(
            self,
            sp: bool = True,
            opcodetxt: bool = True,
            opcodewidth: int = 40) -> str:
        lines: List[str] = []

        def f(iaddr: str, instr: I.Instruction) -> None:
            line = instr.to_string(
                sp=sp, opcodetxt=opcodetxt, opcodewidth=opcodewidth)
            lines.append(str(iaddr).rjust(10) + "  " + line)
        self.iter(f)
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.to_string()
