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
"""Compares two basic blocks in two related functions in different binaries."""

from typing import Any, Dict, List, Mapping, Optional, Tuple, TYPE_CHECKING

from chb.jsoninterface.JSONResult import JSONResult
from chb.relational.InstructionRelationalAnalysis import (
    InstructionRelationalAnalysis)

import chb.relational.relationalutil as UR
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
        self._distance: int = -1
        self._instrmapping: Dict[str, str] = {}
        self._revinstrmapping: Dict[str, str] = {}
        self._instranalyses: Dict[str, InstructionRelationalAnalysis] = {}
        self._instrbytes: Dict[str, Tuple[List[str], List[str]]] = {}

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
    def b1len(self) -> int:
        return len(self.b1.instructions)

    @property
    def b2len(self) -> int:
        return len(self.b2.instructions)

    @property
    def distance(self) -> int:
        """Return the levenshtein distance between the instruction bytes."""

        return self._distance

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
            (dist, mapping) = self.levenshtein_distance()
            self._distance = dist
            self.match_instructions(mapping)
        return self._instrmapping

    @property
    def rev_instr_mapping(self) -> Mapping[str, str]:
        if len(self._revinstrmapping) == 0:
            mapping = self.instr_mapping
        return self._revinstrmapping

    def levenshtein_distance(self) -> Tuple[
            int, List[Tuple[Optional[int], Optional[int]]]]:
        s1 = [i.bytestring for (a, i) in sorted(self.b1.instructions.items())]
        s2 = [i.bytestring for (a, i) in sorted(self.b2.instructions.items())]
        return UR.levenshtein(s1, s2)

    def match_instructions(
            self, mapping: List[Tuple[Optional[int], Optional[int]]]) -> None:
        b1addrs = sorted(self.b1.instructions.keys())
        b2addrs = sorted(self.b2.instructions.keys())
        for (x, y) in mapping:
            if x is not None and y is not None:
                self._instrmapping[b1addrs[x]] = b2addrs[y]
                self._revinstrmapping[b2addrs[y]] = b1addrs[x]

    @property
    def instr_analyses(self) -> Mapping[str, InstructionRelationalAnalysis]:
        if len(self._instranalyses) == 0:
            for iaddr1 in self.b1.instructions:
                if iaddr1 in self.instr_mapping:
                    iaddr2 = self.instr_mapping[iaddr1]
                    if iaddr2 in self.b2.instructions:
                        instr2: Optional["Instruction"] = self.b2.instructions[iaddr2]
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

    def instrs_changed(self, callees: List[str]) -> List[str]:
        result: List[str] = []
        for iaddr in self.instr_analyses:
            ira = self.instr_analyses[iaddr]
            if len(callees) > 0 and (not ira.calls_function(callees)):
                continue
            if ira.is_mapped and ira.is_changed:
                result.append(iaddr)
        return result

    def instrs_added(self) -> List[str]:
        result: List[str] = []
        for iaddr2 in self.b2.instructions:
            if iaddr2 not in self.rev_instr_mapping:
                result.append(iaddr2)
        return result

    def instrs_deleted(self) -> List[str]:
        result: List[str] = []
        for iaddr1 in self.b1.instructions:
            if iaddr1 not in self.instr_mapping:
                result.append(iaddr1)
        return result

    def to_json_result(self) -> JSONResult:
        schema = "blockcomparison"
        content: Dict[str, Any] = {}
        content["baddr1"] = self.b1.baddr
        content["baddr2"] = self.b2.baddr
        content["lev-distance"] = self.distance
        content["changes"] = []
        content["matches"] = []
        bsummary = self.block_comparison_summary_result()
        if bsummary.is_ok:
            content["block-comparison-summary"] = bsummary.content
        else:
            return JSONResult(schema, {}, "fail", bsummary.reason)
        bdetails = self.block_comparison_details_result()
        if bdetails.is_ok:
            content["block-comparison-details"] = bdetails.content
        else:
            return JSONResult(schema, {}, "fail", bdetails.reason)

        return JSONResult(schema, content, "ok")

    def block_comparison_summary_result(self) -> JSONResult:
        schema = "blockcomparisonsummary"
        content: Dict[str, Any] = {}
        binstrs = self.instructions_comparison_summary_result()
        if binstrs.is_ok:
            content["block-instructions-comparison-summary"] = binstrs.content
        else:
            return JSONResult(schema, {}, "fail", binstrs.reason)
        bsem = self.semantics_comparison_summary_result()
        if bsem.is_ok:
            content["block-semantics-comparison-summary"] = bsem.content
        else:
            return JSONResult(schema, {}, "fail", bsem.reason)

        return JSONResult(schema, content, "ok")

    def instructions_comparison_summary_result(self) -> JSONResult:
        schema = "blockinstructionscomparisonsummary"
        content: Dict[str, Any] = {}
        content["changes"] = []
        imapped: List[Dict[str, Any]] = []
        for iaddr in self.instr_analyses:
            iresult = self.instruction_mapped_summary_result(iaddr)
            if iresult.is_ok:
                imapped.append(iresult.content)
            else:
                return JSONResult(schema, {}, "fail", iresult.reason)
        content["block-instructions-mapped"] = imapped
        content["block-insturctions-added"] = self.instrs_added()
        content["block-instructions-removed"] = self.instrs_deleted()

        return JSONResult(schema, content, "ok")

    def instruction_mapped_summary_result(self, iaddr: str) -> JSONResult:
        schema = "blockinstructionmappedsummary"
        content: Dict[str, Any] = {}
        content["iaddr"] = iaddr
        content["changes"] = {}
        content["matches"] = {}

        return JSONResult(schema, content, "ok")

    def semantics_comparison_summary_result(self) -> JSONResult:
        schema = "blocksemanticscomparisonsummary"
        content: Dict[str, Any] = {}
        return JSONResult(schema, content, "ok")

    def block_comparison_details_result(self) -> JSONResult:
        schema = "blockcomparisondetails"
        content: Dict[str, Any] = {}
        imapped: List[Dict[str, Any]] = []
        for (iaddr, ira) in self.instr_analyses.items():
            if ira.is_changed and ira.is_mapped:
                iresult = ira.to_json_result()
                if iresult.is_ok:
                    imapped.append(iresult.content)
                else:
                    return JSONResult(schema, {}, "fail", iresult.reason)
        content["instruction-comparisons"] = imapped
        content["instructions-added"] = []
        content["instructions-removed"] = []

        return JSONResult(schema, content, "ok")

    def report(self, callees: List[str] = []) -> str:
        lines: List[str] = []
        for iaddr in self.instr_analyses:
            ira = self.instr_analyses[iaddr]
            if (
                    not ira.is_md5_equal
                    or ira.has_different_annotation
                    or (not ira.same_address)):
                if len(callees) > 0:
                    if not (ira.calls_function(callees) and ira.has_different_annotation):
                        continue
                if ira.is_mapped:
                    moved = "" if ira.same_address else " (moved)"
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
                        + str(ira.instr2)
                        + moved)
                    lines.append("")

                else:
                    b1 = ira.instr1.bytestring
                    lines.append(
                        "  V:"
                        + ira.instr1.iaddr
                        + "  "
                        + b1
                        + "  "
                        + str(ira.instr1))
                    lines.append("  P: not mapped")
                    lines.append("")

        for iaddr2 in self.b2.instructions:

            def calls(callees: List[str], ann: str) -> bool:
                for c in callees:
                    if c in ann and "call" in ann:
                        return True
                else:
                    return False

            if iaddr2 not in self.rev_instr_mapping:
                b2instr = self.b2.instructions[iaddr2]
                if len(callees) > 0 and calls(callees, b2instr.annotation):
                    pass

                b2bytes = b2instr.bytestring
                lines.append("  V: not mapped")
                lines.append(
                    "  P:" + iaddr2 + "  " + b2bytes + "  " + str(b2instr))
                lines.append("")

        return "\n".join(lines)
