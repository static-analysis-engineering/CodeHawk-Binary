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
        self.add_txt(summary_header())
        obj.app_comparison_summary.accept(self)
        if self.details:
            obj.app_comparison_details.accept(self)

    def visit_app_comparison_details(
            self, obj: AppC.JSONAppComparisonDetails) -> None:
        self.add_txt(details_header())
        for f in obj.function_comparisons:
            f.accept(self)

    def visit_app_comparison_summary(
            self, obj: AppC.JSONAppComparisonSummary) -> None:
        obj.functions_summary.accept(self)

    def visit_app_function_mapped_summary(
            self, obj: AppC.JSONAppFunctionMappedSummary) -> None:
        self.add_txt(
            obj.faddr.ljust(20)
            + (obj.moved_to if obj.moved_to is not None else "not moved").ljust(16)
            + ("yes" if "md5" in obj.matches else "no").ljust(12)
            + ("yes" if "md5" in obj.matches or "cfg" in obj.matches else "no").ljust(18)
            + (str(obj.blocks_changed) if obj.blocks_changed is not None else "-"))

    def visit_app_functions_comparison_summary(
            self, obj: AppC.JSONAppFunctionsComparisonSummary) -> None:
        for f in obj.app_functions_mapped:
            f.accept(self)

    def visit_assembly_instruction(self, obj: JSONAssemblyInstruction) -> None:
        pass

    def visit_callgraph_comaprison_summary(
            self, obj: AppC.JSONCallgraphComparisonSummary) -> None:
        pass

    def visit_block_comparison(
            self, obj: BlockC.JSONBlockComparison) -> None:
        pass

    def visit_block_comparison_details(
            self, obj: BlockC.JSONBlockComparisonDetails) -> None:
        pass

    def visit_block_comparison_summary(
            self, obj: BlockC.JSONBlockComparisonSummary) -> None:
        pass

    def visit_block_instruction_mapped_summary(
            self, obj: BlockC.JSONBlockInstructionMappedSummary) -> None:
        pass

    def visit_block_instructions_comparison_summary(
            self, obj: BlockC.JSONBlockInstructionsComparisonSummary) -> None:
        pass

    def visit_block_semantics_comparison_summary(
            self, obj: BlockC.JSONBlockSemanticsComparisonSummary) -> None:
        pass

    def visit_cfg_comparison_summary(
            self, obj: FunC.JSONCfgComparisonSummary) -> None:
        pass

    def visit_function_block_mapped_summary(
            self, obj: FunC.JSONFunctionBlockMappedSummary) -> None:
        self.add_txt(
            obj.baddr.ljust(12)
            + (obj.moved_to if obj.moved_to is not None else "no").ljust(16)
            + ("yes" if "md5" in obj.matches else "no").ljust(18)
            + "?")

    def visit_function_blocks_comparison_summary(
            self, obj: FunC.JSONFunctionBlocksComparisonSummary) -> None:
        for f in obj.function_blocks_mapped:
            f.accept(self)

    def visit_function_comparison(
            self, obj: FunC.JSONFunctionComparison) -> None:
        self.add_txt(function_comparison_header())
        obj.function_comparison_summary.accept(self)
        obj.function_comparison_details.accept(self)

    def visit_function_comparison_summary(
            self, obj: FunC.JSONFunctionComparisonSummary) -> None:
        obj.function_blocks_comparison_summary.accept(self)

    def visit_function_comparison_details(
            self, obj: FunC.JSONFunctionComparisonDetails) -> None:
        pass

    def visit_function_variables_comparison_summary(
            self, obj: FunC.JSONFunctionVariablesComparisonSummary) -> None:
        pass

    def visit_globals_comparison_summary(
            self, obj: AppC.JSONGlobalsComparisonSummary) -> None:
        pass

    def visit_instruction_added_info(
            self, obj: InstrC.JSONInstructionAddedInfo) -> None:
        pass

    def visit_instruction_comparison(
            self, obj: InstrC.JSONInstructionComparison) -> None:
        pass

    def visit_instruction_removed_info(
            self, obj: InstrC.JSONInstructionRemovedInfo) -> None:
        pass
