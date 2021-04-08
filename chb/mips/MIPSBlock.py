# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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

import chb.app.BasicBlock as B
import chb.util.fileutil as UF

from chb.mips.MIPSInstruction import MIPSInstruction

from typing import Dict, List, Mapping, Sequence, TYPE_CHECKING

if TYPE_CHECKING:
    import chb.mips.MIPSFunction


class MIPSBlock(B.BasicBlock):

    def __init__(
            self,
            mipsf: "chb.mips.MIPSFunction.MIPSFunction",
            xnode: ET.Element) -> None:
        B.BasicBlock.__init__(self, mipsf, xnode)
        self._instructions: Dict[str, MIPSInstruction] = {}

    @property
    def instructions(self) -> Dict[str, MIPSInstruction]:
        if len(self._instructions) == 0:
            for n in self.xnode.findall("i"):
                iaddr = n.get("ia")
                if iaddr is None:
                    raise UF.CHBError("ARM Instruction without address in xml")
                self._instructions[iaddr] = MIPSInstruction(self, n)
        return self._instructions

    def get_sliced_instructions(self,registers):
        result = []
        for ia in sorted(self.instructions):
            instr = self.instructions[ia]
            if instr.refers_to_register(registers):
                result.append(instr)
        return result

    @property
    def call_instructions(self) -> Sequence[MIPSInstruction]:
        result: List[MIPSInstruction] = []

        def f(_,i):
            if i.is_call_instruction():
                result.append(i)

        self.iter(f)
        return result

    def to_sliced_string(self,registers,loopdepth):
        lines = []
        for ia in sorted(self.instructions):
            instr = self.instructions[ia]
            looplevel = ('L' * loopdepth).ljust(4)
            if instr.refers_to_register(registers):
                lines.append(str(ia).rjust(10) + ' ' + looplevel
                                 + '  ' + instr.to_string(sp=True,opcodetxt=True))
        return '\n'.join(lines)

    def get_last_instruction(self):
        lastaddr = sorted(self.instructions.keys())[-2]
        return self.instructions[lastaddr]

    def has_return(self):
        return self.get_last_instruction().is_return_instruction()

    def get_return_expr(self):
        return self.get_last_instruction().get_return_expr()
