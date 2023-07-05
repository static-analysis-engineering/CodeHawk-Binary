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

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union

import chb.jsoninterface.JSONAppComparison as AppC
from chb.jsoninterface.JSONAssemblyInstruction import JSONAssemblyInstruction
import chb.jsoninterface.JSONBlockComparison as BlockC
import chb.jsoninterface.JSONFunctionComparison as FunC
import chb.jsoninterface.JSONInstructionComparison as InstrC


class JSONObjectVisitor(ABC):

    def __init__(self) -> None:
        pass

    def visit_app_comparison(self, obj: AppC.JSONAppComparison) -> None:
        ...

    def visit_app_comparison_details(
            self, obj: AppC.JSONAppComparisonDetails) -> None:
        ...

    def visit_app_comparison_summary(
            self, obj: AppC.JSONAppComparisonSummary) -> None:
        ...

    def visit_app_function_mapped_summary(
            self, obj: AppC.JSONAppFunctionMappedSummary) -> None:
        ...

    def visit_app_functions_comparison_summary(
            self, obj: AppC.JSONAppFunctionsComparisonSummary) -> None:
        ...

    def visit_assembly_instruction(self, obj: JSONAssemblyInstruction) -> None:
        ...

    def visit_callgraph_comaprison_summary(
            self, obj: AppC.JSONCallgraphComparisonSummary) -> None:
        ...

    def visit_block_comparison(
            self, obj: BlockC.JSONBlockComparison) -> None:
        ...

    def visit_block_comparison_details(
            self, obj: BlockC.JSONBlockComparisonDetails) -> None:
        ...

    def visit_block_comparison_summary(
            self, obj: BlockC.JSONBlockComparisonSummary) -> None:
        ...

    def visit_block_instruction_mapped_summary(
            self, obj: BlockC.JSONBlockInstructionMappedSummary) -> None:
        ...

    def visit_block_instructions_comparison_summary(
            self, obj: BlockC.JSONBlockInstructionsComparisonSummary) -> None:
        ...

    def visit_block_semantics_comparison_summary(
            self, obj: BlockC.JSONBlockSemanticsComparisonSummary) -> None:
        ...

    def visit_cfg_comparison_summary(
            self, obj: FunC.JSONCfgComparisonSummary) -> None:
        ...

    def visit_function_block_mapped_summary(
            self, obj: FunC.JSONFunctionBlockMappedSummary) -> None:
        ...

    def visit_function_blocks_comparison_summary(
            self, obj: FunC.JSONFunctionBlocksComparisonSummary) -> None:
        ...

    def visit_function_comparison(
            self, obj: FunC.JSONFunctionComparison) -> None:
        ...

    def visit_function_comparison_summary(
            self, obj: FunC.JSONFunctionComparisonSummary) -> None:
        ...

    def visit_function_comparison_details(
            self, obj: FunC.JSONFunctionComparisonDetails) -> None:
        ...

    def visit_function_variables_comparison_summary(
            self, obj: FunC.JSONFunctionVariablesComparisonSummary) -> None:
        ...

    def visit_globals_comparison_summary(
            self, obj: AppC.JSONGlobalsComparisonSummary) -> None:
        ...

    def visit_instruction_added_info(
            self, obj: InstrC.JSONInstructionAddedInfo) -> None:
        ...

    def visit_instruction_comparison(
            self, obj: InstrC.JSONInstructionComparison) -> None:
        ...

    def visit_instruction_removed_info(
            self, obj: InstrC.JSONInstructionRemovedInfo) -> None:
        ...