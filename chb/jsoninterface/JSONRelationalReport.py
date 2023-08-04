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
