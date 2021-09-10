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
"""Compares two binaries."""

from typing import Dict, List, Mapping, Sequence, TYPE_CHECKING

from chb.relational.FunctionRelationalAnalysis import FunctionRelationalAnalysis
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess


class RelationalAnalysis:

    def __init__(self, app1: "AppAccess", app2: "AppAccess") -> None:
        self._app1 = app1
        self._app2 = app2
        self._faddrs1 = sorted(app1.appfunction_addrs)
        self._faddrs2 = sorted(app2.appfunction_addrs)
        self._functionmapping: Dict[str, str] = {}
        self._functionanalyses: Dict[str, FunctionRelationalAnalysis] = {}

    @property
    def app1(self) -> "AppAccess":
        return self._app1

    @property
    def app2(self) -> "AppAccess":
        return self._app2

    @property
    def faddrs1(self) -> Sequence[str]:
        return self._faddrs1

    @property
    def faddrs2(self) -> Sequence[str]:
        return self._faddrs2

    @property
    def fncount1(self) -> int:
        return len(self._faddrs1)

    @property
    def fncount2(self) -> int:
        return len(self._faddrs2)

    @property
    def function_analyses(self) -> Mapping[str, FunctionRelationalAnalysis]:
        if len(self._functionanalyses) == 0:
            for faddr1 in self.faddrs1:
                if faddr1 in self.function_mapping:
                    faddr2 = self.function_mapping[faddr1]
                else:
                    faddr2 = faddr1
                fn1 = self.app1.function(faddr1)
                fn2 = self.app2.function(faddr2)
                self._functionanalyses[faddr1] = FunctionRelationalAnalysis(
                    self.app1, fn1, self.app2, fn2)
        return self._functionanalyses

    def function_analysis(self, faddr: str) -> FunctionRelationalAnalysis:
        if faddr in self.function_analyses:
            return self.function_analyses[faddr]
        else:
            raise UF.CHBError("Address not found in function relational analyses")

    @property
    def is_structurally_equivalent(self) -> bool:
        return (self.fncount1 == self.fncount2
                and len(set(self.faddrs1) - set(self.faddrs2)) == 0)

    @property
    def function_mapping(self) -> Mapping[str, str]:
        if len(self._functionmapping) > 0:
            return self._functionmapping
        elif (
                self.fncount1 == self.fncount2
                and not self.is_structurally_equivalent):
            result: Dict[str, str] = {}
            diff1 = sorted(set(self.faddrs1) - set(self.faddrs2))
            diff2 = sorted(set(self.faddrs2) - set(self.faddrs1))
            for (faddr1, faddr2) in zip(diff1, diff2):
                result[faddr1] = faddr2
            self._functionmapping = result
            return self._functionmapping
        else:
            return {}

    def functions_changed(self) -> List[str]:
        """Return a list of functions that moved or are not md5-equivalent."""

        result: List[str] = []
        for faddr in self.function_analyses:
            if (
                    faddr in self.function_mapping
                    or not self.function_analyses[faddr].is_md5_equal):
                result.append(faddr)

        return result

    def blocks_changed(self, faddr: str) -> List[str]:
        if faddr in self.function_analyses:
            frelanalysis = self.function_analyses[faddr]
            if frelanalysis.is_structurally_equivalent:
                return frelanalysis.blocks_changed()
        return []

    def report(self, showfunctions: bool, showinstructions: bool) -> str:
        lines: List[str] = []
        lines.append("Summary Report")
        lines.append("=" * 80)
        lines.append("")
        lines.append(
            "function".ljust(12)
            + "moved to".ljust(12)
            + "md5-equivalent".ljust(20)
            + "structurally-equivalent".ljust(32)
            + "blocks-changed".ljust(12))
        lines.append("-" * 88)
        for faddr in self.functions_changed():
            fra = self.function_analyses[faddr]
            if faddr in self.function_mapping:
                moved = self.function_mapping[faddr]
            else:
                moved = "no move"
            md5eq = "yes" if fra.is_md5_equal else "no"
            if fra.is_structurally_equivalent:
                streq = "yes"
                blockschanged = len(fra.blocks_changed())
                allblocks = len(fra.basic_blocks1)
                blchg = str(blockschanged) + "/" + str(allblocks)
            else:
                streq = "no"
                blchg = "?"
            lines.append(
                faddr.ljust(12)
                + moved.ljust(16)
                + md5eq.ljust(20)
                + streq.ljust(32)
                + blchg.ljust(12))

        if showfunctions or showinstructions:
            lines.append("")
            lines.append("=" * 80)
            lines.append("Functions changed")
            lines.append("=" * 80)
            for faddr in self.functions_changed():
                fra = self.function_analyses[faddr]
                if fra.is_structurally_equivalent:
                    lines.append("\nFunction " + faddr)
                    lines.append(fra.report(showinstructions))

        return "\n".join(lines)
