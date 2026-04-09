# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2026  Aarno Labs LLC
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


from typing import List, Tuple

import chb.jsoninterface.JSONAppComparison as AppC
from chb.jsoninterface.JSONAssemblyBlock import JSONAssemblyBlock
from chb.jsoninterface.JSONAssemblyInstruction import JSONAssemblyInstruction
import chb.jsoninterface.JSONBlockComparison as BlockC
import chb.jsoninterface.JSONControlFlowGraph as Cfg
import chb.jsoninterface.JSONFunctionComparison as FunC
import chb.jsoninterface.JSONInstructionComparison as InstrC
from chb.jsoninterface.JSONObject import JSONObject
from chb.jsoninterface.JSONObjectNOPVisitor import JSONObjectNOPVisitor
from chb.jsoninterface.JSONProofObligationRecord import (
    JSONProofObligationRecord)


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

    def add_txt_tuple_lst(
            self, lst: List[Tuple[str, str]], tag: str = "") -> None:
        txtlst = (
            "["
            + ", ".join("(" + s1 + "," + s2 + ")" for (s1, s2) in lst)
            + "]")
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
        self.add_txt_lst(
            obj.functions_compared, tag="functions-compared")
        self.add_txt_lst(
            obj.functions_removed, tag="functions-removed")
        self.add_txt(
            "functions-changed[" + str(len(obj.functions_changed)) + "]")
        self.inc_indent()
        for c in obj.functions_changed:
            c.accept(self)
        self.dec_indent()
        self.add_txt("functions-added[" + str(len(obj.functions_added)) + "]")
        self.inc_indent()
        for a in obj.functions_added:
            a.accept(self)
        self.dec_indent()
        obj.callgraph_comparison.accept(self)
        self.add_txt_lst(
            obj.globalvars_compared, tag="globalvars-compared")
        self.add_txt(
            "globalvars-changed[" + str(len(obj.globalvars_changed)) + "]")
        self.inc_indent()
        for g in obj.globalvars_changed:
            g.accept(self)
        self.dec_indent()
        obj.binary_comparison.accept(self)

    def visit_assembly_block(self, obj: JSONAssemblyBlock) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.startaddr, tag="startaddr")
        if len(obj.instructions) > 0:
            self.add_txt("instructions")
            self.inc_indent()
            for instr in obj.instructions:
                if len(instr.proofobligations) > 0:
                    instr.accept(self)
            self.dec_indent()
        self.dec_indent()

    def visit_assembly_instruction(self, obj: JSONAssemblyInstruction) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt_lst(obj.addr, tag="iaddr")
        self.add_txt(obj.opcode[0] + " " + obj.opcode[1], tag="opcode")
        self.add_txt(obj.annotation, tag="annotation")
        for po in obj.proofobligations:
            po.accept(self)
        self.dec_indent()

    def visit_binary_comparison(self, obj: AppC.JSONBinaryComparison) -> None:
        pass

    def visit_block_comparison(
            self, obj: BlockC.JSONBlockComparison) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        if len(obj.summary_instructions_added) > 0:
            self.add_txt_lst(obj.summary_instructions_added, tag="instrs added")
        if len(obj.summary_instructions_removed) > 0:
            self.add_txt_lst(obj.summary_instructions_removed, tag="instrs removed")
        if len(obj.summary_instructions_changed) > 0:
            self.add_txt_lst(obj.summary_instructions_changed, tag="instrs changed")
        for ia in obj.instructions_added:
            ia.accept(self)
        for ir in obj.instructions_removed:
            ir.accept(self)
        for ic in obj.instructions_changed:
            ic.accept(self)
        self.dec_indent()

    def visit_callgraph_comparison(
            self, obj: AppC.JSONCallgraphComparison) -> None:
        self.add_newline()
        self.add_txt_lst(obj.changes, tag="changes")

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

    def visit_cfg_block_mapping_item(
            self, obj: FunC.JSONCfgBlockMappingItem) -> None:
        if len(obj.changes) == 0:
            return
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.cfg1_block_addr, tag="baddr1")
        self.add_txt_lst(obj.changes, tag="changes")
        self.add_txt_lst(obj.matches, tag="matches")
        if obj.block_comparison is not None:
            obj.block_comparison.accept(self)
        self.dec_indent()

    def visit_function_added(
            self, obj: AppC.JSONFunctionAdded) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.faddr, tag="faddr")
        self.dec_indent()

    def visit_function_comparison(
            self, obj: FunC.JSONFunctionComparison) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.faddr1, tag="faddr1")
        self.add_txt(obj.faddr2, tag="faddr2")
        self.add_txt_lst(obj.changes, tag="changes")
        self.add_txt_lst(obj.matches, tag="matches")
        self.add_txt("cfg1")
        self.inc_indent()
        obj.cfg1.accept(self)
        self.dec_indent()
        self.add_txt("cfg2")
        self.inc_indent()
        obj.cfg2.accept(self)
        self.dec_indent()
        self.add_txt_lst(obj.blocks_changed, tag="blocks-changed")
        self.add_txt("block-mapping")
        self.inc_indent()
        for m in obj.cfg_block_mapping:
            m.accept(self)
        self.dec_indent()
        self.dec_indent()

    def visit_globalvar_comparison(
            self, obj: AppC.JSONGlobalVarComparison) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.gaddr, tag="gaddr")
        if obj.name is not None:
            self.add_txt(obj.name, tag="name")
        if obj.moved_to is not None:
            self.add_txt(obj.moved_to, tag="moved-to")
        self.dec_indent()

    def visit_instruction_comparison(
            self, obj: InstrC.JSONInstructionComparison) -> None:
        self.add_newline()
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.iaddr1, tag="iaddr1")
        if obj.iaddr2 and obj.iaddr1 != obj.iaddr2:
            self.add_txt(obj.iaddr2, tag="iaddr2")
        self.add_txt_lst(obj.changes, tag="changes")
        if "bytes" in obj.changes:
            self.add_txt("opcode")
            self.inc_indent()
            self.add_txt(
                obj.instr1.opcode[0] + " " + obj.instr1.opcode[1], tag="instr1")
            if obj.instr2 is not None:
                self.add_txt(
                    obj.instr2.opcode[0] + " " + obj.instr2.opcode[1], tag="instr2")
            self.dec_indent()
        if "semantics" in obj.changes:
            self.add_txt("semantics")
            self.inc_indent()
            self.add_txt(obj.instr1.annotation, tag="instr1")
            if obj.instr2 is not None:
                self.add_txt(obj.instr2.annotation, tag="instr2")
            self.dec_indent()
        if "proofobligations" in obj.changes:
            self.add_txt("proofobligations")
            if len(obj.pos_added) > 0:
                self.inc_indent()
                self.add_txt("added")
                self.inc_indent()
                for po in obj.pos_added:
                    po.accept(self)
                self.dec_indent()
                self.dec_indent()
            if len(obj.pos_removed) > 0:
                self.inc_indent()
                self.add_txt("removed")
                self.inc_indent()
                for po in obj.pos_removed:
                    po.accept(self)
                self.dec_indent()
                self.dec_indent()
        self.dec_indent()

    def visit_proofobligation_record(self, obj: JSONProofObligationRecord) -> None:
        self.add_txt(obj.objname)
        self.inc_indent()
        self.add_txt(obj.predicate, tag="predicate")
        self.add_txt(obj.status, tag="status")
        if obj.msg != "none":
            self.add_txt(obj.msg, tag="msg")
        self.dec_indent()
