# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs, LLC
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
"""Creates a mapping of basic blocks and edges between two executables."""

from typing import Any, Dict, List, Mapping, Optional, Tuple, TYPE_CHECKING

from chb.jsoninterface.JSONResult import JSONResult
from chb.relational.InstructionRelationalAnalysis import (
    InstructionRelationalAnalysis)

import chb.relational.relationalutil as UR
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.BasicBlock import BasicBlock
    from chb.app.Cfg import Cfg
    from chb.app.Instruction import Instruction
    from chb.relational.CfgMatcher import CfgMatcher


class TrampolineAnalysis:

    def __init__(
            self,
            app1: "AppAccess",
            b1: "BasicBlock",
            app2: "AppAccess",
            trampoline: List["BasicBlock"],
            cfgmatcher: "CfgMatcher") -> None:
        self._app1 = app1
        self._app2 = app2
        self._b1 = b1
        self._trampoline = trampoline
        self._cfgmatcher = cfgmatcher
        self._instrmapping: Dict[str, str] = {}
        self._revinstrmapping: Dict[str, str] = {}
        self._instranalyses: Dict[str, InstructionRelationalAnalysis] = {}
        self._distance: int = -1

    @property
    def app1(self) -> "AppAccess":
        return self._app1

    @property
    def app2(self) -> "AppAccess":
        return self._app2

    @property
    def cfgmatcher(self) -> "CfgMatcher":
        return self._cfgmatcher

    @property
    def cfg2(self) -> "Cfg":
        return self.cfgmatcher.cfg2

    @property
    def b1(self) -> "BasicBlock":
        return self._b1

    @property
    def trampoline(self) -> List["BasicBlock"]:
        return self._trampoline

    @property
    def distance(self) -> int:
        return self._distance

    @property
    def spliced_blocks(self) -> Tuple["BasicBlock", "BasicBlock"]:
        firstblock: Optional["BasicBlock"] = None
        lastblock: Optional["BasicBlock"] = None
        for b2 in self.trampoline:
            if b2.baddr == self.b1.baddr:
                firstblock = b2
            elif b2.lastaddr == self.b1.lastaddr:
                lastblock = b2
        if firstblock is None or lastblock is None:
            raise UF.CHBError("No spliced blocks found")
        return (firstblock, lastblock)

    @property
    def trampoline_setup(self) -> str:
        (s2start, s2end) = self.spliced_blocks
        if s2start.baddr in self.cfg2.edges:
            if len(self.cfg2.edges[s2start.baddr]) == 1:
                return self.cfg2.edges[s2start.baddr][0]
        raise UF.CHBError("No setup block found")

    @property
    def trampoline_setup_block(self) -> "BasicBlock":
        addr = self.trampoline_setup
        for b in self.trampoline:
            if b.baddr == addr:
                return b
        raise UF.CHBError("Trampoline setup block not found")

    @property
    def trampoline_function(self) -> str:
        setup = self.trampoline_setup
        if setup in self.cfg2.edges:
            if len(self.cfg2.edges[setup]) == 1:
                return self.cfg2.edges[setup][0]
        raise UF.CHBError("No trampoline function found")

    @property
    def trampoline_decision(self) -> str:
        tf = self.trampoline_function
        if tf in self.cfg2.edges:
            if len(self.cfg2.edges[tf]) == 1:
                return self.cfg2.edges[tf][0]
        raise UF.CHBError("No trampoline decision block found")

    @property
    def trampoline_takedown(self) -> str:
        (s2start, s2end) = self.spliced_blocks
        td = self.trampoline_decision
        if td in self.cfg2.edges:
            for succ in self.cfg2.edges[td]:
                if succ in self.cfg2.edges:
                    if len(self.cfg2.edges[succ]) == 1:
                        if self.cfg2.edges[succ][0] == s2end.baddr:
                            return succ
        raise UF.CHBError("No trampoline takedown block found")

    @property
    def trampoline_takedown_block(self) -> "BasicBlock":
        addr = self.trampoline_takedown
        for b in self.trampoline:
            if b.baddr == addr:
                return b
        raise UF.CHBError("Trampoline takedown block not found")

    @property
    def trampoline_breakout(self) -> str:
        (s2start, s2end) = self.spliced_blocks
        td = self.trampoline_decision
        if td in self.cfg2.edges:
            for succ in self.cfg2.edges[td]:
                if succ == self.trampoline_takedown:
                    continue
                return succ
        raise UF.CHBError("No trampoline breakout block found")

    def levenshtein_distance(self) -> Tuple[
            int, List[Tuple[Optional[int], Optional[int]]]]:
        (b2start, b2end) = self.spliced_blocks
        s2start = list((i.bytestring for (a, i) in sorted(b2start.instructions.items())))
        s2end = list((i.bytestring for (a, i) in sorted(b2end.instructions.items())))
        s2 = s2start + s2end
        s1 = list((i.bytestring for (a, i) in sorted(self.b1.instructions.items())))
        return UR.levenshtein(s1, s2)

    @property
    def instr_mapping(self) -> Mapping[str, str]:
        if len(self._instrmapping) == 0:
            (dist, mapping) = self.levenshtein_distance()
            self._distance = dist
            self.match_instructions(mapping)
        return self._instrmapping

    @property
    def rev_instr_mapping(self) -> Mapping[str, str]:
        if len(self._revinstrmapping) == 0:
            mapping = self.instr_mapping
        return self._revinstrmapping    

    def match_instructions(
            self, mapping: List[Tuple[Optional[int], Optional[int]]]) -> None:
        b1addrs = sorted(self.b1.instructions.keys())
        (b2start, b2end) = self.spliced_blocks
        b2startaddrs = sorted(b2start.instructions.keys())
        b2endaddrs = sorted(b2end.instructions.keys())
        b2addrs = b2startaddrs + b2endaddrs
        for (x, y) in mapping:
            if x is not None and y is not None:
                self._instrmapping[b1addrs[x]] = b2addrs[y]
                self._revinstrmapping[b2addrs[y]] = b1addrs[x]

    @property
    def instr_analyses(self) -> Mapping[str, InstructionRelationalAnalysis]:
        (b2start, b2end) = self.spliced_blocks
        if len(self._instranalyses) == 0:
            for iaddr1 in self.b1.instructions:
                if iaddr1 in self.instr_mapping:
                    iaddr2 = self.instr_mapping[iaddr1]
                    if iaddr2 in b2start.instructions:
                        instr2: Optional["Instruction"] = b2start.instructions[iaddr2]
                    elif iaddr2 in b2end.instructions:
                        instr2 = b2end.instructions[iaddr2]
                    else:
                        instr2 = None
                    self._instranalyses[iaddr1] = InstructionRelationalAnalysis(
                        self.app1,
                        self.b1.instructions[iaddr1],
                        self.app2,
                        instr2)
                else:
                    self._instranalyses[iaddr1] = InstructionRelationalAnalysis(
                        self.app1,
                        self.b1.instructions[iaddr1],
                        self.app2,
                        None)
        return self._instranalyses

    def report(self, callees: List[str] = []) -> str:
        lines: List[str] = []
        for iaddr in sorted(self.instr_analyses):
            ira = self.instr_analyses[iaddr]
            if (
                    not ira.is_md5_equal
                    or ira.has_different_annotation
                    or (not ira.same_address)):

                if ira.is_mapped:
                    moved = "" if ira.same_address else " (moved)"
                    b1 = ira.instr1.bytestring
                    b2 = ira.instr2.bytestring
                    lines.append(
                        "  V:"
                        + ira.instr1.iaddr
                        + "  "
                        + b1.ljust(8)
                        + "  "
                        + str(ira.instr1))
                    lines.append(
                        "  P:"
                        + ira.instr2.iaddr
                        + "  "
                        + b2.ljust(8)
                        + "  "
                        + str(ira.instr2)
                        + moved)
                    lines.append("")

                else:
                    b1 = ira.instr1.bytestring
                    lines.append(
                        "  V:"
                        + ira.instr1.iaddr
                        + "  "
                        + b1.ljust(8)
                        + "  "
                        + str(ira.instr1))
                    lines.append("  P: not mapped")
                    lines.append("")

        lines.append("\nTrampoline setup   : " + self.trampoline_setup)
        lines.append("Trampoline function: " + self.trampoline_function)
        lines.append("Trampoline decision: " + self.trampoline_decision)
        lines.append("Trampoline takedown: " + self.trampoline_takedown)
        lines.append("Trampoline breakout: " + self.trampoline_breakout)

        lines.append("\nTrampoline takedown:")
        for instr in self.trampoline_takedown_block.instructions.values():
            lines.append(instr.iaddr.ljust(10) + instr.bytestring.ljust(10) + str(instr))

        

        return "\n".join(lines)
            
            
        
            
        
