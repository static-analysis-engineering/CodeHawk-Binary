# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2024  Aarno Labs LLC
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
"""Pretty printer for code represented as an abstract syntax tree."""

from typing import cast, Dict, List, Optional, Set, TYPE_CHECKING

from chb.ast.ASTCPrettyPrinter import ASTCPrettyPrinter
import chb.ast.ASTNode as AST

if TYPE_CHECKING:
    from chb.ast.ASTSymbolTable import ASTGlobalSymbolTable, ASTLocalSymbolTable
    from chb.astinterface.ASTIProvenance import ASTIProvenance
    from chb.invariants.VarInvariantFact import (
        ReachingDefFact,
        VarInvariantFact
    )


class ASTICPrettyPrinter(ASTCPrettyPrinter):

    def __init__(
            self,
            localsymboltable: "ASTLocalSymbolTable",
            provenance: "ASTIProvenance",
            indentation: int = 2,
            annotations: Dict[int, List[str]] = {},
            livevars_on_exit: Dict[int, Set[str]] = {}) -> None:
        ASTCPrettyPrinter.__init__(
            self,
            localsymboltable,
            indentation=indentation,
            annotations=annotations,
            livevars_on_exit=livevars_on_exit)
        self._provenance = provenance
        self._instr_reachingdefs: List[str] = []

    @property
    def instr_reachingdefs(self) -> List[str]:
        """Return reachingdefs that were added since last reset.

        Reaching definitions are being added automatcally when subexpressions
        are visited.
        """

        return self._instr_reachingdefs

    def add_reachingdefs(self, rdefs: List["ReachingDefFact"]) -> None:
        self._instr_reachingdefs.extend(str(r) for r in rdefs)

    def reset_reachingdefs(self) -> None:
        self._instr_reachingdefs = []

    @property
    def provenance(self) -> "ASTIProvenance":
        return self._provenance

    def visit_branch_stmt(self, stmt: AST.ASTBranch) -> None:
        condition = stmt.condition
        if self.provenance.has_reaching_defs(condition.exprid):
            rdefs = self.provenance.get_reaching_defs(condition.exprid)
        else:
            rdefs = []
        if self.provenance.has_expression_mapped(condition.exprid):
            ll_condition = self.provenance.get_expression_mapped(condition.exprid)
            if self.provenance.has_flag_reaching_defs(ll_condition.exprid):
                flagrdefs = self.provenance.get_flag_reaching_defs(
                    ll_condition.exprid)
            else:
                flagrdefs = []

            self.ccode.newline(indent=self.indent)
            self.ccode.write("// " + ("-" * 60))
            self.ccode.newline(indent=self.indent)
            self.ccode.write("// ")
            if self.provenance.has_condition_address(ll_condition.exprid):
                conditionaddr = ",".join(
                    self.provenance.get_condition_address(ll_condition.exprid))
                self.ccode.write(conditionaddr)
            self.ccode.write(" ll-condition: ")
            ll_condition.accept(self)
            self.ccode.newline(indent=self.indent)
            self.ccode.write("// ")
            for rdef in rdefs:
                self.ccode.newline(indent=self.indent)
                self.ccode.write("// " + str(rdef))
            for frdef in flagrdefs:
                self.ccode.newline(indent=self.indent)
                self.ccode.write("// " + str(frdef))
            self.ccode.newline(indent=self.indent)
            self.ccode.write("// " + "-" * 60)
        else:
            print("No expression mapped for " + str(condition))

        ASTCPrettyPrinter.visit_branch_stmt(self, stmt)

    def visit_assign_instr(self, instr: AST.ASTAssign) -> None:
        ASTCPrettyPrinter.visit_assign_instr(self, instr)
        if self.provenance.has_instruction_mapped(instr.instrid):
            mapped_instrs = (
                self.provenance.get_instructions_mapped(instr.instrid))
            for (i, mapped_instr) in enumerate(mapped_instrs):
                if i > 0:
                    self.ccode.newline(indent=self.indent)
                self.ccode.write(" " * (60 - self.ccode.pos))
                self.ccode.write("// ")
                if mapped_instr.is_ast_assign:
                    mapped_instr = cast(AST.ASTAssign, mapped_instr)
                    if self.provenance.has_instruction_address(instr.instrid):
                        address = ", ".join(
                            self.provenance.get_instruction_address(
                                instr.instrid))
                        self.ccode.write(address)
                        self.ccode.write("  ")
                    mapped_instr.lhs.accept(self)
                    self.ccode.write(" = ")
                    mapped_instr.rhs.accept(self)
                    self.ccode.write(";")
                else:
                    mapped_instr = cast(AST.ASTCall, mapped_instr)
                    if self.provenance.has_instruction_address(instr.instrid):
                        address = ", ".join(
                            self.provenance.get_instruction_address(
                                instr.instrid))
                        self.ccode.write(address)
                        self.ccode.write("  ")
                    if mapped_instr.lhs is not None:
                        mapped_instr.lhs.accept(self)
                        self.ccode.write(" = ")
                    mapped_instr.tgt.accept(self)
                    self.ccode.write(";")

            for rdefstring in self.instr_reachingdefs:
                self.ccode.newline(indent=self.indent + 4)
                self.ccode.write("  // " + rdefstring)
            self.reset_reachingdefs()
            if self.provenance.has_lval_defuse(instr.lhs.lvalid):
                self.ccode.newline(indent=self.indent + 4)
                defuse = self.provenance.get_lval_defuse(instr.lhs.lvalid)
                self.ccode.write("  // ")
                self.ccode.write(str(defuse))
            if self.provenance.has_lval_defuse_high(instr.lhs.lvalid):
                self.ccode.newline(indent=self.indent + 4)
                defusehigh = self.provenance.get_lval_defuse_high(
                    instr.lhs.lvalid)
                self.ccode.write("  // ")
                self.ccode.write(str(defusehigh))

    def visit_call_instr(self, instr: AST.ASTCall) -> None:
        ASTCPrettyPrinter.visit_call_instr(self, instr)
        if self.provenance.has_instruction_mapped(instr.instrid):
            mapped_instrs = (
                self.provenance.get_instructions_mapped(instr.instrid))
            for (i, mapped_instr) in enumerate(mapped_instrs):
                mapped_instr = cast(AST.ASTCall, mapped_instr)
                if i > 0:
                    self.ccode.newline(indent=self.indent)
                self.ccode.write(" " * (60 - self.ccode.pos))
                self.ccode.write("// ")
                if self.provenance.has_instruction_address(instr.instrid):
                    address = ", ".join(
                        self.provenance.get_instruction_address(instr.instrid))
                    self.ccode.write(address)
                    self.ccode.write("  ")
                if mapped_instr.lhs is not None:
                    mapped_instr.lhs.accept(self)
                    self.ccode.write(" = ")
                mapped_instr.tgt.accept(self)
                self.ccode.write("(")
                if len(mapped_instr.arguments) > 0:
                    for llarg in mapped_instr.arguments[:-1]:
                        llarg.accept(self)
                        self.ccode.write(", ")
                    mapped_instr.arguments[-1].accept(self)
                self.ccode.write(");")
            for rdefstring in self.instr_reachingdefs:
                self.ccode.newline(indent=self.indent + 5)
                self.ccode.write("  // " + rdefstring)
            self.reset_reachingdefs()
            if instr.lhs is not None:
                if self.provenance.has_lval_defuse(instr.lhs.lvalid):
                    self.ccode.newline(indent=self.indent + 4)
                    defuse = self.provenance.get_lval_defuse(instr.lhs.lvalid)
                    self.ccode.write("  // ")
                    self.ccode.write(str(defuse))
                if self.provenance.has_lval_defuse_high(instr.lhs.lvalid):
                    self.ccode.newline(indent=self.indent + 4)
                    defusehigh = self.provenance.get_lval_defuse_high(
                        instr.lhs.lvalid)
                    self.ccode.write("  // ")
                    self.ccode.write(str(defusehigh))

    def visit_asm_instr(self, instr: AST.ASTAsm) -> None:
        ASTCPrettyPrinter.visit_asm_instr(self, instr)
        if self.provenance.has_instruction_mapped(instr.instrid):
            mapped_instrs = (
                self.provenance.get_instructions_mapped(instr.instrid))
            for (i, mapped_instr) in enumerate(mapped_instrs):
                mapped_instr = cast(AST.ASTCall, mapped_instr)
                if i > 0:
                    self.ccode.newline(indent=self.indent)
                self.ccode.write(" " * (60 - self.ccode.pos))
                self.ccode.write("// ")
                if self.provenance.has_instruction_address(instr.instrid):
                    address = ", ".join(
                        self.provenance.get_instruction_address(instr.instrid))
                    self.ccode.write(address)
                    self.ccode.write("  ")
                if mapped_instr.lhs is not None:
                    mapped_instr.lhs.accept(self)
                    self.ccode.write(" = ")
                mapped_instr.tgt.accept(self)
                self.ccode.write(";")
            for rdefstring in self.instr_reachingdefs:
                self.ccode.newline(indent=self.indent + 5)
                self.ccode.write("  // " + rdefstring)
            self.reset_reachingdefs()

    def visit_lval_expression(self, lvalexpr: AST.ASTLvalExpr) -> None:
        if self.provenance.has_reaching_defs(lvalexpr.exprid):
            rdefs = self.provenance.get_reaching_defs(lvalexpr.exprid)
            self.add_reachingdefs(rdefs)
        lvalexpr.lval.accept(self)

    def visit_binary_expression(self, binopexpr: AST.ASTBinaryOp) -> None:
        if self.provenance.has_reaching_defs(binopexpr.exprid):
            rdefs = self.provenance.get_reaching_defs(binopexpr.exprid)
            self.add_reachingdefs(rdefs)
        ASTCPrettyPrinter.visit_binary_expression(self, binopexpr)

    def visit_memref(self, memref: AST.ASTMemRef) -> None:
        if self.provenance.has_reaching_defs(memref.memexp.exprid):
            rdefs = self.provenance.get_reaching_defs(memref.memexp.exprid)
            self.add_reachingdefs(rdefs)
        ASTCPrettyPrinter.visit_memref(self, memref)
