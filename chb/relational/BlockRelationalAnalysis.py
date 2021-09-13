# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs, LLC
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
"""Compares two basic blocks in two related functions in different binaries."""

from typing import Dict, List, Mapping, Optional, TYPE_CHECKING

from chb.relational.InstructionRelationalAnalysis import (
    InstructionRelationalAnalysis)

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.BasicBlock import BasicBlock
    from chb.app.Instruction import Instruction


class BlockRelationalAnalysis:

    def __init__(
            self,
            app1: "AppAccess",
            b1: "BasicBlock",
            app2: "AppAccess",
            b2: "BasicBlock") -> None:
        self._app1 = app1
        self._app2 = app2
        self._b1 = b1
        self._b2 = b2
        self._instrmapping: Dict[str, str] = {}
        self._instranalyses: Dict[str, InstructionRelationalAnalysis] = {}

    @property
    def app1(self) -> "AppAccess":
        return self._app1

    @property
    def app2(self) -> "AppAccess":
        return self._app2

    @property
    def b1(self) -> "BasicBlock":
        return self._b1

    @property
    def b2(self) -> "BasicBlock":
        return self._b2

    @property
    def offset(self) -> int:
        return int(self.b2.baddr, 16) - int(self.b1.baddr, 16)

    @property
    def same_endianness(self) -> bool:
        return self.app1.header.is_big_endian == self.app2.header.is_big_endian

    @property
    def is_md5_equal(self) -> bool:
        if self.same_endianness:
            return self.b1.md5() == self.b2.md5()
        else:
            return self.b1.md5() == self.b2.rev_md5()

    @property
    def instr_mapping(self) -> Mapping[str, str]:
        if len(self._instrmapping) == 0:
            for iaddr1 in self.b1.instructions:
                self._instrmapping[iaddr1] = hex(int(iaddr1, 16) + self.offset)
        return self._instrmapping

    @property
    def instr_analyses(self) -> Mapping[str, InstructionRelationalAnalysis]:
        if len(self._instranalyses) == 0:
            for (iaddr1, iaddr2) in self.instr_mapping.items():
                if iaddr2 in self.b2.instructions:
                    instr2: Optional["Instruction"] = self.b2.instructions[iaddr2]
                else:
                    instr2 = None
                self._instranalyses[iaddr1] = InstructionRelationalAnalysis(
                    self.app1,
                    self.b1.instructions[iaddr1],
                    self.app2,
                    instr2)
        return self._instranalyses

    def instrs_changed(self) -> List[str]:
        result: List[str] = []
        for iaddr in self.instr_analyses:
            if not self.instr_analyses[iaddr].is_md5_equal:
                result.append(iaddr)
        return result

    def report(self) -> str:
        lines: List[str] = []
        for iaddr in self.instr_analyses:
            ira = self.instr_analyses[iaddr]
            if not ira.is_md5_equal and not ira.is_semantically_equal:
                if ira.is_mapped:
                    b1 = ira.instr1.bytestring
                    if self.same_endianness:
                        b2 = ira.instr2.bytestring
                    else:
                        b2 = ira.instr2.rev_bytestring
                    lines.append(
                        "  V:"
                        + ira.instr1.iaddr
                        + "  "
                        + b1
                        + "  "
                        + str(ira.instr1))
                    lines.append(
                        "  P:"
                        + ira.instr2.iaddr
                        + "  "
                        + b2
                        + "  "
                        + str(ira.instr2))
                    lines.append("")
                else:
                    lines.append(
                        "  V:"
                        + ira.instr1.iaddr
                        + "  "
                        + b1
                        + "  "
                        + str(ira.instr1))
                    lines.append("  P: not mapped")
                    lines.append("")
        return "\n".join(lines)
