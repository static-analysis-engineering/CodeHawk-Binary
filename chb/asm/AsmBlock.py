# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyrigth (c) 2021      Aarno Labs, LLC
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
"""X86 assembly function basic block."""

import xml.etree.ElementTree as ET

from typing import Dict, List, Mapping, Sequence, TYPE_CHECKING

import chb.app.BasicBlock as B
import chb.app.Function as F
import chb.util.fileutil as UF

from chb.asm.AsmInstruction import AsmInstruction

class AsmBlock(B.BasicBlock):

    def __init__(self,f: F.Function, xnode: ET.Element) -> None:
        B.BasicBlock.__init__(self, f, xnode)
        self._instructions: Dict[str, AsmInstruction] = {}

    @property
    def instructions(self) -> Mapping[str, AsmInstruction]:
        if len(self._instructions) == 0:
            for n in self.xnode.findall("i"):
                iaddr = n.get("ia")
                if iaddr is None:
                    raise UF.CHBError("X86 Instruction without address in xml")
                self._instructions[iaddr] = AsmInstruction(self, n)
        return self._instructions

    @property
    def call_instructions(self) -> Sequence[AsmInstruction]:
        result: List[AsmInstruction] = []

        def f(_,i):
            if i.is_call_instruction():
                result.append(i)

        self.iter(f)
        return result

    def to_opcode_operations_string(self):
        lines = []
        for ia in sorted(self.instructions):
            lines.append(str(ia).rjust(10) + '  '
                             + self.instructions[ia].to_opcode_operations_string())
        return '\n'.join(lines)

    def to_string(self,bytestring=False,bytes=False,esp=False,opcodetxt=True,
                  opcodewidth=25):
        lines = []
        for ia in sorted(self.instructions):
            pinstr = self.instructions[ia].to_string(bytestring=bytestring,
                                                     bytes=bytes,
                                                     esp=esp,
                                                     opcodewidth=opcodewidth,
                                                     opcodetxt=opcodetxt)
            lines.append(str(ia).rjust(10) + '  ' + pinstr)
        return '\n'.join(lines)

    def get_last_instruction(self):
        lastaddr = sorted(self.instructions.keys())[-1]
        return self.instructions[lastaddr]

    def has_return(self):
        return self.get_last_instruction().is_return_instruction()

    def get_return_expr(self):
        return self.get_last_instruction().get_return_expr()

    def as_dictionary(self):
        result = {}
        self._get_instructions()
        for iaddr in sorted(self.instructions):
            instr = {}
            i = self.instructions[iaddr]
            instr['iaddr'] = iaddr
            instr['opcode'] = i.get_opcode_text()
            instr['bytes'] = i.get_byte_string()
            instr['esp'] = str(i.get_esp_offset())
            instr['annotation'] = i.get_annotation()
            result[iaddr] = instr
        return result
