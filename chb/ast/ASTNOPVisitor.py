# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022 Aarno Labs LLC
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
"""Full implementation of ASTVisitor without any operations."""

import chb.ast.ASTNode as AST
from chb.ast.ASTVisitor import ASTVisitor


class ASTNOPVisitor(ASTVisitor):

    def __init__(self) -> None:
        pass

    def visit_return_stmt(self, stmt: AST.ASTReturn) -> None:
        pass

    def visit_break_stmt(self, stmt: AST.ASTBreak) -> None:
        pass

    def visit_continue_stmt(self, stmt: AST.ASTContinue) -> None:
        pass

    def visit_loop_stmt(self, stmt: AST.ASTLoop) -> None:
        pass

    def visit_block_stmt(self, stmt: AST.ASTBlock) -> None:
        pass

    def visit_instruction_sequence_stmt(
            self, stmt: AST.ASTInstrSequence) -> None:
        pass

    def visit_branch_stmt(self, stmt: AST.ASTBranch) -> None:
        pass

    def visit_goto_stmt(self, stmt: AST.ASTGoto) -> None:
        pass

    def visit_computedgoto_stmt(self, stmt: AST.ASTComputedGoto) -> None:
        pass

    def visit_switch_stmt(self, stmt: AST.ASTSwitchStmt) -> None:
        pass

    def visit_label(self, label: AST.ASTLabel) -> None:
        pass

    def visit_case_label(self, label: AST.ASTCaseLabel) -> None:
        pass

    def visit_case_range_label(self, label: AST.ASTCaseRangeLabel) -> None:
        pass

    def visit_default_label(self, label: AST.ASTDefaultLabel) -> None:
        pass

    def visit_nop_instr(self, instr: AST.ASTNOPInstruction) -> None:
        pass

    def visit_assign_instr(self, instr: AST.ASTAssign) -> None:
        pass

    def visit_call_instr(self, instr: AST.ASTCall) -> None:
        pass

    def visit_asm_instr(self, instr: AST.ASTAsm) -> None:
        pass

    def visit_lval(self, lval: AST.ASTLval) -> None:
        pass

    def visit_varinfo(self, vinfo: AST.ASTVarInfo) -> None:
        pass

    def visit_variable(self, var: AST.ASTVariable) -> None:
        pass

    def visit_memref(self, memref: AST.ASTMemRef) -> None:
        pass

    def visit_no_offset(self, nooffset: AST.ASTNoOffset) -> None:
        pass

    def visit_field_offset(self, fieldoffset: AST.ASTFieldOffset) -> None:
        pass

    def visit_index_offset(self, indexoffset: AST.ASTIndexOffset) -> None:
        pass

    def visit_integer_constant(
            self, intconstant: AST.ASTIntegerConstant) -> None:
        pass

    def visit_global_address(
            self, globalddress: AST.ASTGlobalAddressConstant) -> None:
        pass

    def visit_string_constant(
            self, stringconstant: AST.ASTStringConstant) -> None:
        pass

    def visit_floating_point_constant(
            self, constant: AST.ASTFloatingPointConstant) -> None:
        pass

    def visit_lval_expression(self, expr: AST.ASTLvalExpr) -> None:
        pass

    def visit_cast_expression(self, expr: AST.ASTCastExpr) -> None:
        pass

    def visit_sizeof_expression(self, expr: AST.ASTSizeOfExpr) -> None:
        pass

    def visit_unary_expression(self, expr: AST.ASTUnaryOp) -> None:
        pass

    def visit_binary_expression(self, expr: AST.ASTBinaryOp) -> None:
        pass

    def visit_question_expression(self, expr: AST.ASTQuestion) -> None:
        pass

    def visit_address_of_expression(self, expr: AST.ASTAddressOf) -> None:
        pass

    def visit_start_of_expression(self, expr: AST.ASTStartOf) -> None:
        pass

    def visit_void_typ(self, typ: AST.ASTTypVoid) -> None:
        pass

    def visit_integer_typ(self, typ: AST.ASTTypInt) -> None:
        pass

    def visit_float_typ(self, typ: AST.ASTTypFloat) -> None:
        pass

    def visit_pointer_typ(self, typ: AST.ASTTypPtr) -> None:
        pass

    def visit_array_typ(self, typ: AST.ASTTypArray) -> None:
        pass

    def visit_fun_typ(self, typ: AST.ASTTypFun) -> None:
        pass

    def visit_funargs(self, funargs: AST.ASTFunArgs) -> None:
        pass

    def visit_funarg(self, funarg: AST.ASTFunArg) -> None:
        pass

    def visit_named_typ(self, typ: AST.ASTTypNamed) -> None:
        pass

    def visit_builtin_va_list(self, typ: AST.ASTTypBuiltinVAList) -> None:
        pass

    def visit_compinfo(self, cinfo: AST.ASTCompInfo) -> None:
        pass

    def visit_fieldinfo(self, finfo: AST.ASTFieldInfo) -> None:
        pass

    def visit_comp_typ(self, typ: AST.ASTTypComp) -> None:
        pass

    def visit_enum_typ(self, typ: AST.ASTTypEnum) -> None:
        pass

    def visit_enuminfo(self, einfo: AST.ASTEnumInfo) -> None:
        pass

    def visit_enumitem(self, eitem: AST.ASTEnumItem) -> None:
        pass
