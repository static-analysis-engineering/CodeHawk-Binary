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

from typing import Callable, cast, Dict, List, Mapping, Sequence, TYPE_CHECKING

from chb.app.BasicBlock import BasicBlock
from chb.app.FunctionDictionary import FunctionDictionary
from chb.app.Instruction import Instruction

from chb.invariants.XXpr import XXpr

import chb.util.fileutil as UF

from chb.x86.X86Instruction import X86Instruction

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.X86Function import X86Function


class X86Block(BasicBlock):

    def __init__(
            self,
            x86fn: "X86Function",
            xnode: ET.Element) -> None:
        BasicBlock.__init__(self, xnode)
        self._x86fn = x86fn
        self._instructions: Dict[str, X86Instruction] = {}

    @property
    def x86function(self) -> "X86Function":
        return self._x86fn

    @property
    def x86dictionary(self) -> "X86Dictionary":
        return self.x86function.x86dictionary

    @property
    def x86functiondictionary(self) -> "FunctionDictionary":
        return self.x86function.x86functiondictionary

    @property
    def instructions(self) -> Mapping[str, X86Instruction]:
        if len(self._instructions) == 0:
            for n in self.xnode.findall("i"):
                iaddr = n.get("ia")
                if iaddr is None:
                    raise UF.CHBError("X86 Instruction without address in xml")
                self._instructions[iaddr] = X86Instruction(self, n)
        return self._instructions

    @property
    def call_instructions(self) -> Sequence[Instruction]:
        result: List[Instruction] = []
        for instr in self.instructions.values():
            if instr.is_call_instruction:
                result.append(instr)
        return result

    @property
    def store_instructions(self) -> Sequence[Instruction]:
        return []

    def iter_instructions(self, f: Callable[[str, X86Instruction], None]) -> None:
        for (ia, instr) in sorted(self.instructions.items()):
            f(ia, instr)

    @property
    def store_instruction(self) -> Sequence[Instruction]:
        return []

    @property
    def strings_referenced(self) -> Sequence[str]:
        return []

    def to_opcode_operations_string(self) -> str:
        lines: List[str] = []
        for (ia, instr) in sorted(self.instructions.items()):
            lines.append(str(ia).rjust(10) + "  "
                         + instr.to_opcode_operations_string())
        return "\n".join(lines)

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
                opcodewidth=opcodewidth,
                opcodetxt=opcodetxt,
                sp=sp)
            lines.append(str(ia).rjust(10) + "  " + pinstr)
        return "\n".join(lines)

    def as_dictionary(self) -> Dict[str, Dict[str, str]]:
        result: Dict[str, Dict[str, str]] = {}
        for (ia, instr) in sorted(self.instructions.items()):
            instrd: Dict[str, str] = {}
            instrd["iaddr"] = ia
            instrd["opcode"] = instr.opcodetext
            instrd["bytes"] = instr.bytestring
            instrd["esp"] = str(instr.stackpointer_offset)
            instrd["annotation"] = instr.annotation
            result[ia] = instrd
        return result
