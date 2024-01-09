# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024  Aarno Labs, LLC
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
"""Analyzes a block that is split into multiple blocks."""

from typing import Any, cast, Dict, List, Mapping, Optional, Tuple, TYPE_CHECKING

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
    from chb.arm.ARMInstruction import ARMInstruction
    from chb.relational.CfgMatcher import CfgMatcher


class SplitBlockAnalysis:

    def __init__(
            self,
            app1: "AppAccess",
            block1: "BasicBlock",
            app2: "AppAccess",
            blocks2: List["BasicBlock"],
            cfgmatcher: "CfgMatcher") -> None:
        self._app1 = app1
        self._app2 = app2
        self._block1 = block1
        self._blocks2 = blocks2
        self._cfgmatcher = cfgmatcher
        self._instrmapping: Dict[str, str] = {}
        self._revinstrmapping: Dict[str, str] = {}
        self._instranalyses: Dict[str, InstructionRelationalAnalysis] = {}
        self._distance: int = -1
        self._roles: Optional[Dict[str, str]] = None

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
    def cfgmatcher(self) -> "CfgMatcher":
        return self.cfgmatcher

    @property
    def cfg1(self) -> "Cfg":
        return self.cfgmatcher.cfg1

    @property
    def cfg2(self) -> "Cfg":
        return self.cfgmatcher.cfg2

    @property
    def block1(self) -> "BasicBlock":
        return self._block1

    @property
    def blocks2(self) -> List["BasicBlock"]:
        return self._blocks2

    @property
    def roles(self) -> Dict[str, str]:
        if self._roles is None:
            self._roles = {}
            if len(self.blocks2) == 2:
                self._roles[self.blocks2[0].baddr] = "split-block-pre"
                self._roles[self.blocks2[1].baddr] = "split-block-post"
            elif len(self.blocks2) == 3:
                self._roles[self.blocks2[0].baddr] = "split-block-pre"
                self._roles[self.blocks2[1].baddr] = "block-insert"
                self._roles[self.blocks2[2].baddr] = "split-block-post"
        return self._roles

    @property
    def distance(self) -> int:
        return self._distance

    @property
    def split_blocks(self) -> Tuple["BasicBlock", "BasicBlock"]:
        return (self.blocks2[0], self.blocks2[-1])

    @property
    def block_inserted(self) -> Optional["BasicBlock"]:
        if len(self.blocks2) == 3:
            return self.blocks2[1]
        else:
            return None

    def levenshtein_distance(self) -> Tuple[
            int, List[Tuple[Optional[int], Optional[int]]]]:
        (b2start, b2end) = self.split_blocks
        s2start = list((
            i.bytestring for (a, i) in sorted(b2start.instructions.items())))
        s2end = list((
            i.bytestring for (a, i) in sorted(b2end.instructions.items())))
        s2 = s2start + s2end
        s1 = list((
            i.bytestring for (a, i) in sorted(self.block1.instructions.items())))
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
        b1addrs = sorted(self.block1.instructions.keys())
        (b2pre, b2post) = self.split_blocks
        b2preaddrs = sorted(b2pre.instructions.keys())
        b2postaddrs = sorted(b2post.instructions.keys())
        b2addrs = b2preaddrs + b2postaddrs
        for (x, y) in mapping:
            if x is not None and y is not None:
                self._instrmapping[b1addrs[x]] = b2addrs[y]
                self._revinstrmapping[b2addrs[y]] = b1addrs[x]

    @property
    def instr_analyses(self) -> Mapping[str, InstructionRelationalAnalysis]:
        (b2pre, b2post) = self.split_blocks
        if len(self._instranalyses) == 0:
            for ia1 in self.block1.instructions:
                if ia1 in self.instr_mapping:
                    ia2 = self.instr_mapping[ia1]
                    if ia2 in b2pre.instructions:
                        instr2: Optional["Instruction"] = b2pre.instructions[ia2]
                    elif ia2 in b2post.instructions:
                        instr2 = b2post.instructions[ia2]
                    else:
                        instr2 = None
                    self._instranalyses[ia1] = InstructionRelationalAnalysis(
                        self.app1,
                        self.block1.instructions[ia1],
                        self.app2,
                        instr2)
                else:
                    self._instranalyses[ia1] = InstructionRelationalAnalysis(
                        self.app1,
                        self.block1.instructions[ia1],
                        self.app2,
                        None)
        return self._instranalyses

    @property
    def instrs_replaced(self) -> List["Instruction"]:
        result: List["Instruction"] = []
        for (ia, ira) in sorted(self.instr_analyses.items()):
            if (
                    not ira.is_md5_equal
                    or ira.has_different_annotation
                    or (not ira.same_address)):
                result.append(ira.instr1)
        return result

    def report(self) -> str:
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

        for block2 in self.blocks2:
            for iaddr2 in block2.instructions:

                if iaddr2 not in self.rev_instr_mapping:
                    b2instr = block2.instructions[iaddr2]

                    b2bytes = b2instr.bytestring
                    lines.append("  V: not mapped")
                    lines.append(
                        "  P:" + iaddr2 + "  " + b2bytes + "  " + str(b2instr))
                    lines.append("")

        return "\n".join(lines)

    def __str__(self) -> str:
        return self.report()
