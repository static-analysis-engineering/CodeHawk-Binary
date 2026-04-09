# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2026  Aarno Labs, LLC
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
"""Compares two instructions in two related functions in different binaries."""

from typing import Any, cast, Dict, List, Optional, Tuple, TYPE_CHECKING

from chb.jsoninterface.JSONResult import JSONResult
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.FnProofObligations import ProofObligation
    from chb.app.Instruction import Instruction


class InstructionRelationalAnalysis:

    def __init__(
            self,
            app1: "AppAccess",
            i1: "Instruction",
            app2: "AppAccess",
            i2: Optional["Instruction"]) -> None:
        self._app1 = app1
        self._app2 = app2
        self._instr1 = i1
        self._instr2 = i2

    @property
    def app1(self) -> "AppAccess":
        return self._app1

    @property
    def app2(self) -> "AppAccess":
        return self._app2

    @property
    def instr1(self) -> "Instruction":
        return self._instr1

    @property
    def instr2(self) -> "Instruction":
        if self.is_mapped:
            return cast("Instruction", self._instr2)
        else:
            raise UF.CHBError(
                "No corresponding instruction found for " + self.instr1.iaddr)

    @property
    def is_mapped(self) -> bool:
        return self._instr2 is not None

    @property
    def same_endianness(self) -> bool:
        return self.app1.header.is_big_endian == self.app2.header.is_big_endian

    @property
    def same_address(self) -> bool:
        return self.is_mapped and self.instr1.iaddr == self.instr2.iaddr

    @property
    def is_md5_equal(self) -> bool:
        if self.is_mapped:
            if self.same_endianness:
                return self.instr1.md5() == self.instr2.md5()
            else:
                return self.instr1.md5() == self.instr2.rev_md5()
        else:
            return False

    @property
    def is_po_changed(self) -> bool:
        comparison: Tuple[
            List["ProofObligation"], List["ProofObligation"]] = ([], [])
        if self.is_mapped:
            i1pos = self.instr1.proofobligations()
            i2pos = self.instr2.proofobligations()
            if len(i1pos) != len(i2pos):
                return True

            is1pos = {str(po): po for po in i1pos}
            is2pos = {str(po): po for po in i2pos}
            for po1 in is1pos:
                if po1 not in is2pos:
                    comparison[0].append(is1pos[po1])
            for po2 in is2pos:
                if po2 not in is1pos:
                    comparison[1].append(is2pos[po2])
        else:
            return len(self.instr1.proofobligations()) > 0
        return (len(comparison[0]) + len(comparison[1])) > 0

    @property
    def po_changes(self) -> Tuple[List["ProofObligation"],
                                  List["ProofObligation"]]:
        comparison: Tuple[
            List["ProofObligation"], List["ProofObligation"]] = ([], [])
        if self.is_mapped:
            i1pos = self.instr1.proofobligations()
            i2pos = self.instr2.proofobligations()

            is1pos = {str(po): po for po in i1pos}
            is2pos = {str(po): po for po in i2pos}
            for po1 in is1pos:
                if po1 not in is2pos:
                    comparison[0].append(is1pos[po1])
            for po2 in is2pos:
                if po2 not in is1pos:
                    comparison[1].append(is2pos[po2])
        else:
            comparison[0].extend(self.instr1.proofobligations())

        return comparison

    @property
    def is_changed(self) -> bool:
        return len(self.changes) > 0

    @property
    def changes(self) -> List[str]:
        result: List[str] = []
        if not self.same_address:
            result.append("address")
        if not self.is_md5_equal:
            result.append("bytes")
        if self.has_different_annotation:
            result.append("semantics")
        if self.is_po_changed:
            result.append("proofobligations")
        return result

    @property
    def loads_same_string(self) -> bool:
        if self.is_mapped:
            s1 = self.instr1.string_pointer_loaded()
            if s1:
                s2 = self.instr2.string_pointer_loaded()
                if s2:
                    return (s1[0] == s2[0] and s1[1] == s2[1])
                else:
                    return False
            else:
                return False
        else:
            return False

    @property
    def calls_same_function_with_same_args(self) -> bool:
        return False

    @property
    def is_semantically_equal(self) -> bool:
        """Return true if the action taken is equivalent."""

        return (
            self.loads_same_string
            or self.calls_same_function_with_same_args)

    @property
    def has_different_annotation(self) -> bool:
        if self.is_mapped:
            return self.instr1.annotation != self.instr2.annotation
        else:
            return True

    def calls_function(self, callees: List[str]) -> bool:
        annotation = self.instr1.annotation
        if len(callees) == 0:
            return True
        for c in callees:
            if c in annotation and "call" in annotation:
                return True
        else:
            return False

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["iaddr1"] = self.instr1.iaddr
        if self.is_mapped:
            content["iaddr2"] = self.instr2.iaddr
        content["changes"] = self.changes
        if self.is_changed:
            i1result = self.instr1.to_json_result()
            if not i1result.is_ok:
                return JSONResult(
                    "instructioncomparison", {}, "fail", i1result.reason)
            content["instr-1"] = i1result.content
            if self.is_mapped:
                i2result = self.instr2.to_json_result()
                if not i2result.is_ok:
                    return JSONResult(
                        "instructioncomparison", {}, "fail", i2result.reason)
                content["instr-2"] = i2result.content
            if self.is_po_changed:
                (pos1, pos2) = self.po_changes
                content["pos-added"] = posadded = []
                for po in pos1:
                    ipo = po.to_json_result()
                    if not ipo.is_ok:
                        return JSONResult(
                            "instructioncomparison", {}, "fail", ipo.reason)
                    posadded.append(ipo.content)
                content["pos-removed"] = posremoved = []
                for po in pos2:
                    ipo = po.to_json_result()
                    if not ipo.is_ok:
                        return JSONResult(
                            "instructioncomparison", {}, "fail", ipo.reason)
                    posremoved.append(ipo.content)

        return JSONResult("instructioncomparison", content, "ok")
