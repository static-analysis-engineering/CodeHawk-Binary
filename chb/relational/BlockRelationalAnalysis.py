# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs, LLC
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
            b2map: Dict[str, "BasicBlock"]) -> None:
        self._app1 = app1
        self._app2 = app2
        self._b1 = b1
        self._b2map = b2map
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
    def b2map(self) -> Dict[str, "BasicBlock"]:
        return self._b2map

    @property
    def b2(self) -> "BasicBlock":
        return self.b2map["entry"]

    @property
    def b2instructions(self) -> Mapping[str, "Instruction"]:
        if "entry" in self.b2map and "exit" in self.b2map:
            result: Dict[str, "Instruction"] = {}
            for (a, instr) in self.b2map["entry"].instructions.items():
                result[a] = instr
            for (a, instr) in self.b2map["exit"].instructions.items():
                result[a] = instr
            return result
        else:
            return self.b2.instructions

    @property
    def b1len(self) -> int:
        return len(self.b1.instructions)

    @property
    def b2len(self) -> int:
        return sum(len(b.instructions) for b in self.b2map.values())

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
        if len(self.b2map) > 1:
            return False
        else:
            if self.same_endianness:
                return self.b1.md5() == self.b2.md5()
            else:
                return self.b1.md5() == self.b2.rev_md5()

    def _compute_instr_mappings(self) -> None:
        (dist, mapping) = self.levenshtein_distance()
        self._distance = dist
        self.match_instructions(mapping)

    @property
    def instr_mapping(self) -> Mapping[str, str]:
        if len(self._instrmapping) == 0:
            self._compute_instr_mappings()
        return self._instrmapping

    @property
    def rev_instr_mapping(self) -> Mapping[str, str]:
        if len(self._revinstrmapping) == 0:
            self._compute_instr_mappings()
        return self._revinstrmapping

    def changes(self) -> List[str]:
        result: List[str] = []
        if not self.is_md5_equal:
            result.append("md5")
        if self.b1len != self.b2len:
            result.append("instructioncount")
        if self.b1.baddr != self.b2.baddr:
            result.append("moved")
        if len(self.b2map) > 1:
            result.append("blockcount")
        return result

    def matches(self) -> List[str]:
        result: List[str] = []
        if self.is_md5_equal:
            result.append("md5")
        if self.b1len == self.b2len:
            result.append("instructioncount")
        return result

    def levenshtein_distance(self) -> Tuple[
            int, List[Tuple[Optional[int], Optional[int]]]]:
        s1 = [i.bytestring for (a, i) in sorted(self.b1.instructions.items())]
        s2 = [i.bytestring for (a, i) in sorted(self.b2instructions.items())]
        return UR.levenshtein(s1, s2)

    def match_instructions(
            self, mapping: List[Tuple[Optional[int], Optional[int]]]) -> None:
        b1addrs = sorted(self.b1.instructions.keys())
        b2addrs = sorted(self.b2instructions.keys())
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
                    if iaddr2 in self.b2instructions:
                        instr2: Optional["Instruction"] = self.b2instructions[iaddr2]
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
        for iaddr2 in self.b2instructions:
            if iaddr2 not in self.rev_instr_mapping:
                result.append(iaddr2)
        return result

    def instrs_deleted(self) -> List[str]:
        result: List[str] = []
        for iaddr1 in self.b1.instructions:
            if iaddr1 not in self.instr_mapping:
                result.append(iaddr1)
        return result

    def to_json_result(self, callees: List[str]) -> JSONResult:
        schema = "cfgblockmappingitem"

        content: Dict[str, Any] = {}
        content["baddr1"] = self.b1.baddr
        content["instr-count1"] = len(self.b1.instructions)
        content["instr-count2"] = len(self.b2.instructions)
        content["changes"] = self.changes()
        content["matches"] = self.matches()
        content["cfg1-block-addr"] = self.b1.real_baddr

        cfg2blocks: List[Dict[str, Any]] = []
        for (role, block2) in self.b2map.items():
            # XXX: This is weird. What would be the role otherwise?
            if len(self.b2map) == 1:
                role = "single-mapped"
            b2content: Dict[str, Any] = {}
            b2content["cfg2-block-addr"] = block2.real_baddr
            b2content["role"] = role
            cfg2blocks.append(b2content)
        content["cfg2-blocks"] = cfg2blocks

        block_comparison: Dict[str, Any] = {}
        bsummary = self.block_comparison_summary_result(callees)
        if bsummary:
            if not bsummary.is_ok:
                return JSONResult(schema, {}, "fail", bsummary.reason)
            block_comparison["block-comparison-summary"] = bsummary.content

        bdetails = self.block_comparison_details_result()
        if bdetails:
            if not bdetails.is_ok:
                return JSONResult(schema, {}, "fail", bdetails.reason)

            block_comparison["block-comparison-details"] = bdetails.content

        if block_comparison:
            # Can be read back using JSONBlockComparison
            content['blockcomparison'] = block_comparison

        return JSONResult(schema, content, "ok")

    def block_comparison_summary_result(self, callees: List[str]) -> Optional[JSONResult]:
        schema = "blockcomparisonsummary"
        content: Dict[str, Any] = {}
        binstrs = self.instructions_comparison_summary_result(callees)
        if binstrs:
            if not binstrs.is_ok:
                return JSONResult(schema, {}, "fail", binstrs.reason)

            content["block-instructions-comparison-summary"] = binstrs.content

        bsem = self.semantics_comparison_summary_result()
        if bsem:
            if not bsem.is_ok:
                return JSONResult(schema, {}, "fail", bsem.reason)
            content["block-semantics-comparison-summary"] = bsem.content

        if not content:
            return None

        return JSONResult(schema, content, "ok")

    def instructions_comparison_summary_result(self, callees: List[str]) -> Optional[JSONResult]:
        schema = "blockinstructionscomparisonsummary"
        content: Dict[str, Any] = {}

        changes = []
        instrs_changed = self.instrs_changed(callees)
        if instrs_changed:
            content["block-instructions-changed"] = instrs_changed
            changes.append("changed")

        instrs_added = self.instrs_added()
        if instrs_added:
            content["block-instructions-added"] = instrs_added
            changes.append("added")

        instrs_deleted = self.instrs_deleted()
        if instrs_deleted:
            content["block-instructions-removed"] = instrs_deleted
            changes.append("removed")

        if not changes:
            return None

        content["changes"] = changes
        return JSONResult(schema, content, "ok")

    def semantics_comparison_summary_result(self) -> Optional[JSONResult]:
        schema = "blocksemanticscomparisonsummary"
        content: Dict[str, Any] = {}
        if not content:
            return None

        return JSONResult(schema, content, "ok")

    def block_comparison_details_result(self) -> Optional[JSONResult]:
        schema = "blockcomparisondetails"
        content: Dict[str, Any] = {}

        imapped: List[Dict[str, Any]] = []
        for (iaddr, ira) in self.instr_analyses.items():
            if ira.is_changed and ira.is_mapped:
                iresult = ira.to_json_result()
                if not iresult.is_ok:
                    return JSONResult(schema, {}, "fail", iresult.reason)

                imapped.append(iresult.content)

        if imapped:
            content["instructions-changed"] = imapped

        iadded = []
        for iaddr in self.instrs_added():
            ira = self.instr_analyses[iaddr]
            iresult = ira.to_json_result()
            if not iresult.is_ok:
                return JSONResult(schema, {}, "fail", iresult.reason)

            iadded.append(iresult.content)

        if iadded:
            content["instructions-added"] = iadded

        iremoved = []
        for iaddr in self.instrs_deleted():
            ira = self.instr_analyses[iaddr]
            iresult = ira.to_json_result()
            if not iresult.is_ok:
                return JSONResult(schema, {}, "fail", iresult.reason)

            iremoved.append(iresult.content)

        if iremoved:
            content["instructions-removed"] = iremoved

        if not content:
            return None

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

        for iaddr2 in self.b2instructions:

            def calls(callees: List[str], ann: str) -> bool:
                for c in callees:
                    if c in ann and "call" in ann:
                        return True
                else:
                    return False

            if iaddr2 not in self.rev_instr_mapping:
                b2instr = self.b2instructions[iaddr2]
                if len(callees) > 0 and calls(callees, b2instr.annotation):
                    pass

                b2bytes = b2instr.bytestring
                lines.append("  V: not mapped")
                lines.append(
                    "  P:" + iaddr2 + "  " + b2bytes + "  " + str(b2instr))
                lines.append("")

        return "\n".join(lines)
