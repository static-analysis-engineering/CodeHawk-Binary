# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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
import datetime

from typing import Any, Dict, List, Optional, Union

import chb.jsoninterface.JSONAppComparison as AppC
from chb.jsoninterface.JSONAssemblyInstruction import JSONAssemblyInstruction
import chb.jsoninterface.JSONBlockComparison as BlockC
import chb.jsoninterface.JSONFunctionComparison as FunC
import chb.jsoninterface.JSONInstructionComparison as InstrC
from chb.jsoninterface.JSONObjectNOPVisitor import JSONObjectNOPVisitor


def relational_header(xname1: str, xname2: str, header: str) -> str:
    lines: List[str] = []
    lines.append("=" * 80)
    lines.append(
        "||"
        + ("CodeHawk Relational Analysis: " + header).ljust(76)
        + "||")
    lines.append("||" + "  - " + str(xname1).ljust(72) + "||")
    lines.append("||" + "  - " + str(xname2).ljust(72) + "||")
    lines.append("=" * 80)
    return "\n".join(lines)


def relational_footer() -> str:
    lines: List[str] = []
    lines.append("=" * 80)
    lines.append("||" + (str(datetime.datetime.now()) + "  ").rjust(76) + "||")
    lines.append("=" * 80)
    return "\n".join(lines)


def summary_header() -> str:
    lines: List[str] = []
    lines.append(
        "function".ljust(20)
        + "moved to".ljust(12)
        + "md5-equal".ljust(12)
        + "cfg-isomorphic".ljust(18)
        + "blocks-changed".ljust(12))
    lines.append("-" * 80)
    return "\n".join(lines)


def details_header() -> str:
    lines: List[str] = []
    lines.append("")
    lines.append("=" * 80)
    lines.append("Functions changed")
    lines.append("=" * 80)
    return "\n".join(lines)


def function_comparison_header() -> str:
    lines: List[str] = []
    lines.append(
        "block".ljust(12)
        + "moved".ljust(12)
        + "md5-equivalent".ljust(20)
        + "instrs-changed".ljust(20))
    lines.append("-" * 80)
    return "\n".join(lines)


class JSONRelationalReport(JSONObjectNOPVisitor):

    def __init__(self) -> None:
        self._report: List[str] = []
        self._details: bool = False

    @property
    def details(self) -> bool:
        return self._details

    def add_txt(self, s: str) -> None:
        self._report.append(s)

    def summary_report(
            self,
            obj: AppC.JSONAppComparison,
            details: bool = False) -> str:
        self._details = details
        self.add_txt(relational_header(
            obj.file1, obj.file2, "functions comparison"))
        obj.accept(self)
        self.add_txt(relational_footer())
        return "\n".join(self._report)

    def visit_app_comparison(self, obj: AppC.JSONAppComparison) -> None:
        if not obj.functions_changed:
            return

        self.add_txt(summary_header())

        maxnamelen = max(len(n) for n in obj.function_names.values()) + 3

        totalblocks = 0

        # XXX: Should this loop over obj.functions_compared instead so we can
        # report on functions not found? see line 292 in relational/RelationalAnalysis.py
        for fn_changed in obj.functions_changed:
            faddr = fn_changed.faddr1
            fn_name = obj.function_names[faddr]

            if fn_changed.faddr1 != fn_changed.faddr2:
                moved = "moved"
            else:
                moved = "not moved"

            if "md5" in fn_changed.changes:
                md5eq = "no"
            else:
                md5eq = "yes"

            if "cfg-structure" in fn_changed.changes:
                streq = "no"
                blocks1 = fn_changed.block_info["basic_blocks1"]
                blocks2 = fn_changed.block_info["basic_blocks2"]
                blchg = f"{blocks1} -> {blocks2}"

                totalblocks += abs(blocks1 - blocks2)
            else:
                streq = "yes"
                blockschanged = fn_changed.block_info["blocks-changed"]
                allblocks = fn_changed.block_info["basic_blocks1"]
                blchg = str(blockschanged) + "/" + str(allblocks)

                totalblocks += blockschanged

            self.add_txt(
                fn_name.ljust(maxnamelen)
                + moved.ljust(16)
                + md5eq.ljust(12)
                + streq.ljust(18)
                + blchg.ljust(12))

        self.add_txt("\n\nSummary")
        self.add_txt("-" * 80)
        self.add_txt("  Total number of blocks changed: " + str(totalblocks))

        if self.details:
            for fn_changed in obj.functions_changed:
                fn_changed.accept(self)

    def visit_assembly_instruction(self, obj: JSONAssemblyInstruction) -> None:
        pass

    def visit_block_comparison(
            self, obj: BlockC.JSONBlockComparison) -> None:
        pass

    def visit_function_comparison(
            self, obj: FunC.JSONFunctionComparison) -> None:
        self.add_txt(function_comparison_header())

    def visit_instruction_comparison(
            self, obj: InstrC.JSONInstructionComparison) -> None:
        pass
