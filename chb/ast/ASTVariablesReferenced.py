# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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
"""Identifies variables referenced in an ast."""

from typing import Set

import chb.ast.ASTNode as AST
from chb.ast.ASTVisitor import ASTVisitor


class ASTVariablesReferenced(ASTVisitor):

    def __init__(self) -> None:
        self._referenced: Set[str] = set([])

    def variables_referenced(self, stmt: AST.ASTStmt) -> Set[str]:
        """Return the names of all variables referenced in stmt.

        We assume that there is no shadowing for now.
        """

        stmt.accept(self)
        return self._referenced

    def visit_return_stmt(self, stmt: AST.ASTReturn) -> None:
        if stmt.has_return_value():
            stmt.expr.accept(self)

    def visit_break_stmt(self, stmt: AST.ASTBreak) -> None:
        pass

    def visit_continue_stmt(self, stmt: AST.ASTContinue) -> None:
        pass

    def visit_loop_stmt(self, stmt: AST.ASTLoop) -> None:
        for s in stmt.stmts:
            s.accept(self)

    def visit_block_stmt(self, stmt: AST.ASTBlock) -> None:
        for s in stmt.stmts:
            s.accept(self)

    def visit_instruction_sequence_stmt(self, stmt: AST.ASTInstrSequence) -> None:
        for i in stmt.instructions:
            i.accept(self)

    def visit_branch_stmt(self, stmt: AST.ASTBranch) -> None:
        stmt.condition.accept(self)
        stmt.ifstmt.accept(self)
        stmt.elsestmt.accept(self)

    def visit_goto_stmt(self, stmt: AST.ASTGoto) -> None:
        pass

    def visit_switch_stmt(self, stmt: AST.ASTSwitchStmt) -> None:
        stmt.switchexpr.accept(self)
        stmt.cases.accept(self)

    def visit_label(self, label: AST.ASTLabel) -> None:
        pass

    def visit_case_label(self, label: AST.ASTCaseLabel) -> None:
        label.case_expr.accept(self)

    def visit_case_range_label(self, label: AST.ASTCaseRangeLabel) -> None:
        label.lowexpr.accept(self)
        label.highexpr.accept(self)

    def visit_default_label(self, label: AST.ASTDefaultLabel) -> None:
        pass

    def visit_assign_instr(self, instr: AST.ASTAssign) -> None:
        instr.lhs.accept(self)
        instr.rhs.accept(self)

    def visit_call_instr(self, instr: AST.ASTCall) -> None:
        if instr.lhs is not None:
            instr.lhs.accept(self)
        for a in instr.arguments:
            a.accept(self)

    def visit_lval(self, lval: AST.ASTLval) -> None:
        lval.lhost.accept(self)
        lval.offset.accept(self)

    def visit_varinfo(self, vinfo: AST.ASTVarInfo) -> None:
        self._referenced.add(vinfo.vname)

    def visit_variable(self, var: AST.ASTVariable) -> None:
        var.varinfo.accept(self)

    def visit_memref(self, memref: AST.ASTMemRef) -> None:
        memref.memexp.accept(self)

    def visit_no_offset(self, offset: AST.ASTNoOffset) -> None:
        pass

    def visit_field_offset(self, offset: AST.ASTFieldOffset) -> None:
        offset.offset.accept(self)

    def visit_index_offset(self, offset: AST.ASTIndexOffset) -> None:
        offset.index_expr.accept(self)
        offset.offset.accept(self)

    def visit_integer_constant(self, c: AST.ASTIntegerConstant) -> None:
        pass

    def visit_floating_point_constant(
            self, c: AST.ASTFloatingPointConstant) -> None:
        pass

    def visit_global_address(self, g: AST.ASTGlobalAddressConstant) -> None:
        g.address_expr.accept(self)

    def visit_string_constant(self, s: AST.ASTStringConstant) -> None:
        pass

    def visit_lval_expression(self, expr: AST.ASTLvalExpr) -> None:
        expr.lval.accept(self)

    def visit_sizeof_expression(self, expr: AST.ASTSizeOfExpr) -> None:
        expr.tgt_type.accept(self)

    def visit_cast_expression(self, expr: AST.ASTCastExpr) -> None:
        expr.cast_tgt_type.accept(self)
        expr.cast_expr.accept(self)

    def visit_unary_expression(self, unop: AST.ASTUnaryOp) -> None:
        unop.exp1.accept(self)

    def visit_binary_expression(self, binop: AST.ASTBinaryOp) -> None:
        binop.exp1.accept(self)
        binop.exp2.accept(self)

    def visit_question_expression(self, expr: AST.ASTQuestion) -> None:
        expr.exp1.accept(self)
        expr.exp2.accept(self)
        expr.exp3.accept(self)

    def visit_address_of_expression(self, expr: AST.ASTAddressOf) -> None:
        expr.lval.accept(self)

    def visit_void_typ(self, t: AST.ASTTypVoid) -> None:
        pass

    def visit_integer_typ(self, t: AST.ASTTypInt) -> None:
        pass

    def visit_float_typ(self, t: AST.ASTTypFloat) -> None:
        pass

    def visit_pointer_typ(self, t: AST.ASTTypPtr) -> None:
        t.tgttyp.accept(self)

    def visit_array_typ(self, t: AST.ASTTypArray) -> None:
        t.tgttyp.accept(self)
        if t.size_expr is not None:
            t.size_expr.accept(self)

    def visit_fun_typ(self, t: AST.ASTTypFun) -> None:
        t.returntyp.accept(self)
        if t.argtypes is not None:
            t.argtypes.accept(self)

    def visit_funargs(self, funargs: AST.ASTFunArgs) -> None:
        for a in funargs.funargs:
            a.accept(self)

    def visit_funarg(self, funarg: AST.ASTFunArg) -> None:
        funarg.argtyp.accept(self)

    def visit_named_typ(self, t: AST.ASTTypNamed) -> None:
        t.typdef.accept(self)

    def visit_builtin_va_list(self, t: AST.ASTTypBuiltinVAList) -> None:
        pass

    def visit_comp_typ(self, t: AST.ASTTypComp) -> None:
        pass

    def visit_compinfo(self, cinfo: AST.ASTCompInfo) -> None:
        pass

    def visit_fieldinfo(self, finfo: AST.ASTFieldInfo) -> None:
        pass

    def visit_enum_typ(self, t: AST.ASTTypEnum) -> None:
        pass

    def visit_enumitem(self, eitem: AST.ASTEnumItem) -> None:
        pass

    def visit_enuminfo(self, einfo: AST.ASTEnumInfo) -> None:
        pass
