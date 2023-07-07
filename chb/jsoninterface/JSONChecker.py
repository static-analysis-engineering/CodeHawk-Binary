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


from typing import Any, Dict, List, Optional, TYPE_CHECKING

import chb.jsoninterface.JSONAppComparison as AppC
from chb.jsoninterface.JSONAssemblyBlock import JSONAssemblyBlock
from chb.jsoninterface.JSONAssemblyInstruction import JSONAssemblyInstruction
import chb.jsoninterface.JSONBlockComparison as BlockC
import chb.jsoninterface.JSONControlFlowGraph as Cfg
import chb.jsoninterface.JSONCfgComparison as CfgC
import chb.jsoninterface.JSONFunctionComparison as FunC
import chb.jsoninterface.JSONInstructionComparison as InstrC
from chb.jsoninterface.JSONObject import JSONObject
from chb.jsoninterface.JSONObjectNOPVisitor import JSONObjectNOPVisitor


class JSONChecker(JSONObjectNOPVisitor):

    def __init__(self) -> None:
        self._indent: int = 0
        self._txt: List[str] = []
        self._properties_missing: List[str] = []

    def check_object(self, obj: JSONObject) -> str:
        obj.accept(self)
        return "\n".join(self._txt)

    def add_newline(self) -> None:
        self._txt.append("")

    def add_txt(self, t: str, tag: str = "") -> None:
        if len(tag) == 0:
            self._txt.append(self.indentstr + t)
        else:
            self._txt.append(self.indentstr + tag + ": " + t)

    def add_txt_lst(self, lst: List[str], tag: str = "") -> None:
        txtlst = "[" + ", ".join(lst) + "]"
        if len(tag) == 0:
            self._txt.append(self.indentstr + txtlst)
        else:
            self._txt.append(self.indentstr + tag + ": " + txtlst)

    def inc_indent(self, n: int = 2) -> None:
        self._indent += n

    def dec_indent(self, n: int = 2) -> None:
        self._indent -= n

    @property
    def indent(self) -> int:
        return self._indent

    @property
    def indentstr(self) -> str:
        return " " * self.indent

    def visit_app_comparison(self, obj: AppC.JSONAppComparison) -> None:
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt("file1: " + obj.file1)
        self.add_txt("file2: " + obj.file2)
        self.add_txt_lst(obj.changes, tag="changes")
        self.add_txt_lst(obj.matches, tag="matches")
        obj.app_comparison_summary.accept(self)
        obj.app_comparison_details.accept(self)

    def visit_app_comparison_details(
            self, obj: AppC.JSONAppComparisonDetails) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt_lst(
            obj.function_comparisons_omitted, tag="function-comparisons-omitted")
        self.add_txt("function-comparisons[" + str(len(obj.function_comparisons)) + "]")
        self.inc_indent()
        for c in obj.function_comparisons:
            c.accept(self)
        self.dec_indent()
        self.dec_indent()

    def visit_app_comparison_summary(
            self, obj: AppC.JSONAppComparisonSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        obj.functions_summary.accept(self)
        obj.globals_summary.accept(self)
        obj.callgraph_summary.accept(self)
        self.dec_indent()

    def visit_app_function_mapped_summary(
            self, obj: AppC.JSONAppFunctionMappedSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.faddr, tag="faddr")
        if obj.name is not None:
            self.add_txt(obj.name, tag="name")
        self.add_txt_lst(obj.changes, tag="changes")
        self.add_txt_lst(obj.matches, tag="matches")
        if obj.moved_to is not None:
            self.add_txt(obj.moved_to, tag="moved_to")
        self.dec_indent()

    def visit_app_functions_comparison_summary(
            self, obj: AppC.JSONAppFunctionsComparisonSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt_lst(obj.app_functions_added, tag="app-functions-added")
        self.add_txt_lst(obj.app_functions_removed, tag="app-functions-removed")
        self.add_txt("app-functions-mapped[" + str(len(obj.app_functions_mapped)) + "]")
        self.inc_indent()
        for c in obj.app_functions_mapped:
            c.accept(self)
        self.dec_indent()

    def visit_assembly_block(self, obj: JSONAssemblyBlock) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.startaddr, tag="startaddr")
        self.dec_indent()

    def visit_assembly_instruction(self, obj: JSONAssemblyInstruction) -> None:
        pass

    def visit_callgraph_comaprison_summary(
            self, obj: AppC.JSONCallgraphComparisonSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname + " (tbd)")

    def visit_block_comparison(
            self, obj: BlockC.JSONBlockComparison) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.baddr1, tag="baddr1")
        self.add_txt(obj.baddr2, tag="baddr2")
        self.add_txt(str(obj.lev_distance), tag="lev-distance")
        self.add_txt_lst(obj.changes, tag="changes")
        self.add_txt_lst(obj.changes, tag="matches")
        obj.block_comparison_summary.accept(self)
        obj.block_comparison_details.accept(self)
        self.dec_indent()

    def visit_block_comparison_details(
            self, obj: BlockC.JSONBlockComparisonDetails) -> None:
        self.add_newline()
        self.add_txt(obj.objname + " (tbd)")

    def visit_block_comparison_summary(
            self, obj: BlockC.JSONBlockComparisonSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        obj.block_instructions_comparison_summary.accept(self)
        obj.block_semantics_comparison_summary.accept(self)
        self.dec_indent()

    def visit_block_instruction_mapped_summary(
            self, obj: BlockC.JSONBlockInstructionMappedSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.iaddr, tag="iaddr")
        self.add_txt_lst(obj.changes, tag="changes")
        self.add_txt_lst(obj.matches, tag="matches")
        if obj.moved_to is not None:
            self.add_txt(obj.moved_to, tag="moved-to")
        self.dec_indent()

    def visit_block_instructions_comparison_summary(
            self, obj: BlockC.JSONBlockInstructionsComparisonSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt_lst(
            obj.block_instructions_added, tag="block-instructions-added")
        self.add_txt_lst(
            obj.block_instructions_removed, tag="block-instructions-removed")
        self.add_txt(
            "block-instruction-mapped[" + str(len(obj.block_instructions_mapped)) + "]")
        for i in obj.block_instructions_mapped:
            i.accept(self)
        self.dec_indent()

    def visit_block_semantics_comparison_summary(
            self, obj: BlockC.JSONBlockSemanticsComparisonSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname + " (tbd)")

    def visit_cfg_block_mapping_item(
            self, obj: CfgC.JSONCfgBlockMappingItem) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt_lst(obj.changes, tag="changes")
        self.add_txt_lst(obj.matches, tag="matches")
        self.add_txt(obj.cfg1_block_addr, tag="cfg1_block_addr")
        self.add_txt("cfg2-blocks")
        self.inc_indent()
        for (b, role) in obj.cfg2_blocks:
            self.add_txt(b + ", " + role)
        self.dec_indent()
        self.dec_indent()

    def visit_cfg_comparison(self, obj: CfgC.JSONCfgComparison) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt("cfg1")
        self.inc_indent()
        obj.cfg1.accept(self)
        self.dec_indent()
        self.add_txt("cfg2")
        self.inc_indent()
        obj.cfg2.accept(self)
        self.dec_indent()
        self.add_txt("cfg-block-mapping")
        self.inc_indent()
        for m in obj.cfg_block_mapping:
            m.accept(self)
        self.dec_indent()
        self.dec_indent()

    def visit_cfg_comparisons(self, obj: CfgC.JSONCfgComparisons) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        for f in obj.functions_changed:
            f.accept(self)
        self.dec_indent()

    def visit_cfg_comparison_summary(
            self, obj: FunC.JSONCfgComparisonSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname + " (tbd)")

    def visit_cfg_edge(self, obj: Cfg.JSONCfgEdge) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.src, tag="src")
        self.add_txt(obj.tgt, tag="tgt")
        self.add_txt(obj.kind, tag="kind")
        if obj.predicate is not None:
            self.add_txt(obj.predicate, tag="predicate")
        self.dec_indent()

    def visit_cfg_node(self, obj: Cfg.JSONCfgNode) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.baddr, tag="baddr")
        obj.code.accept(self)
        self.dec_indent()

    def visit_control_flow_graph(self, obj: Cfg.JSONControlFlowGraph) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        if obj.name is not None:
            self.add_txt(obj.name, tag="name")
        self.add_txt(obj.faddr, tag="faddr")
        self.add_txt("nodes")
        self.inc_indent()
        for n in obj.nodes:
            n.accept(self)
        self.dec_indent()
        self.add_txt("edges")
        self.inc_indent()
        for e in obj.edges:
            e.accept(self)
        self.dec_indent()
        self.dec_indent()

    def visit_function_block_mapped_summary(
            self, obj: FunC.JSONFunctionBlockMappedSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.baddr, tag="baddr")
        self.add_txt_lst(obj.changes, tag="changes")
        self.add_txt_lst(obj.matches, tag="matches")
        if obj.moved_to is not None:
            self.add_txt(obj.moved_to, tag="moved-to")
        self.dec_indent()

    def visit_function_blocks_comparison_summary(
            self, obj: FunC.JSONFunctionBlocksComparisonSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.add_txt_lst(obj.function_blocks_added, tag="function-blocks-added")
        self.add_txt_lst(obj.function_blocks_removed, tag="function-blocks-removed")
        self.add_txt(
            "function-blocks-mapped[" + str(len(obj.function_blocks_mapped)) + "]")
        for b in obj.function_blocks_mapped:
            b.accept(self)

    def visit_function_comparison(
            self, obj: FunC.JSONFunctionComparison) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.faddr1, tag="faddr1")
        self.add_txt(obj.faddr2, tag="faddr2")
        self.add_txt_lst(obj.changes, tag="changes")
        self.add_txt_lst(obj.matches, tag="matches")
        obj.function_comparison_summary.accept(self)
        obj.function_comparison_details.accept(self)
        self.dec_indent()

    def visit_function_comparison_summary(
            self, obj: FunC.JSONFunctionComparisonSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        obj.cfg_comparison_summary.accept(self)
        obj.function_variables_comparison_summary.accept(self)
        obj.function_blocks_comparison_summary.accept(self)
        self.dec_indent()

    def visit_function_comparison_details(
            self, obj: FunC.JSONFunctionComparisonDetails) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt("block-comparisons[" + str(len(obj.block_comparisons)) + "]")
        self.inc_indent()
        for b in obj.block_comparisons:
            b.accept(self)
        self.dec_indent()

    def visit_function_variables_comparison_summary(
            self, obj: FunC.JSONFunctionVariablesComparisonSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname + " (tbd)")

    def visit_globals_comparison_summary(
            self, obj: AppC.JSONGlobalsComparisonSummary) -> None:
        self.add_newline()
        self.add_txt(obj.objname + " (tbd)")

    def visit_instruction_added_info(
            self, obj: InstrC.JSONInstructionAddedInfo) -> None:
        self.add_newline()
        self.add_txt(obj.objname + " (tbd)")

    def visit_instruction_comparison(
            self, obj: InstrC.JSONInstructionComparison) -> None:
        self.add_newline()
        self.add_txt(obj.objname + " (tbd)")

    def visit_instruction_removed_info(
            self, obj: InstrC.JSONInstructionRemovedInfo) -> None:
        self.add_newline()
        self.add_txt(obj.objname + " (tbd)")

    
