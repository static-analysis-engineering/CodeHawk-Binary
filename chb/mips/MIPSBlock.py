# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2022 Aarno Labs LLC
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
"""Basic block of a MIPS function."""

import xml.etree.ElementTree as ET

from typing import Callable, cast, Dict, List, Mapping, Sequence, TYPE_CHECKING

from chb.app.BasicBlock import BasicBlock

from chb.mips.MIPSInstruction import MIPSInstruction

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.FunctionDictionary import FunctionDictionary
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.mips.MIPSFunction import MIPSFunction


class MIPSBlock(BasicBlock):

    def __init__(
            self,
            mipsfn: "MIPSFunction",
            xnode: ET.Element) -> None:
        BasicBlock.__init__(self, xnode)
        self._mipsfn = mipsfn
        self._instructions: Dict[str, MIPSInstruction] = {}

    @property
    def function(self) -> "MIPSFunction":
        return self._mipsfn

    @property
    def dictionary(self) -> "MIPSDictionary":
        return self.function.dictionary

    @property
    def functiondictionary(self) -> "FunctionDictionary":
        return self.function.functiondictionary

    @property
    def instructions(self) -> Dict[str, MIPSInstruction]:
        if len(self._instructions) == 0:
            for n in self.xnode.findall("i"):
                iaddr = n.get("ia")
                if iaddr is None:
                    raise UF.CHBError("ARM Instruction without address in xml")
                self._instructions[iaddr] = MIPSInstruction(self, n)
        return self._instructions

    def iter(self, f: Callable[[str, MIPSInstruction], None]) -> None:
        for (ia, instr) in self.instructions.items():
            mipsinstr = cast(MIPSInstruction, instr)
            f(ia, mipsinstr)

    def get_sliced_instructions(
            self, registers: List[str]) -> List[MIPSInstruction]:
        result: List[MIPSInstruction] = []
        for ia in sorted(self.instructions):
            instr = self.instructions[ia]
            if instr.refers_to_register(registers):
                result.append(instr)
        return result

    @property
    def call_instructions(self) -> Sequence[MIPSInstruction]:
        result: List[MIPSInstruction] = []

        def f(iaddr: str, i: MIPSInstruction) -> None:
            if i.is_call_instruction:
                result.append(i)

        self.iter(f)
        return result

    def to_sliced_string(self, registers: List[str], loopdepth: int) -> str:
        lines: List[str] = []
        for ia in sorted(self.instructions):
            instr = self.instructions[ia]
            looplevel = ('L' * loopdepth).ljust(4)
            if instr.refers_to_register(registers):
                lines.append(
                    str(ia).rjust(10)
                    + ' '
                    + looplevel
                    + '  '
                    + instr.to_string(sp=True, opcodetxt=True))
        return '\n'.join(lines)

    @property
    def last_instruction(self) -> MIPSInstruction:
        """Override to account for delay slot."""

        lastaddr = sorted(self.instructions.keys())[-1]
        lastinstr = self.instructions[lastaddr]

        if len(self.instructions) > 1:
            instr2addr = sorted(self.instructions.keys())[-2]
            instr2 = self.instructions[instr2addr]
            if (
                    instr2.is_branch_instruction
                    or instr2.is_call_instruction
                    or instr2.is_return_instruction):
                return instr2
            else:
                return lastinstr
        else:
            return lastinstr

    def to_string(
            self,
            bytes: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 25,
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
