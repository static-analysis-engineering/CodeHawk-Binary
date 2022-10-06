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
"""Concrete class for AST transformers that transform nodes into themselves."""

from chb.ast.ASTTransformer import ASTTransformer

import chb.ast.ASTNode as AST


class ASTIdentityTransformer(ASTTransformer):

    def __init__(self) -> None:
        pass

    def transform_return_stmt(self, stmt: AST.ASTReturn) -> AST.ASTStmt:
        return stmt

    def transform_break_stmt(self, stmt: AST.ASTBreak) -> AST.ASTStmt:
        return stmt

    def transform_continue_stmt(self, stmt: AST.ASTContinue) -> AST.ASTStmt:
        return stmt

    def transform_loop_stmt(self, stmt: AST.ASTLoop) -> AST.ASTStmt:
        return stmt

    def transform_block_stmt(self, stmt: AST.ASTBlock) -> AST.ASTStmt:
        return stmt

    def transform_instruction_sequence_stmt(
            self, stmt: AST.ASTInstrSequence) -> AST.ASTStmt:
        return stmt

    def transform_branch_stmt(self, stmt: AST.ASTBranch) -> AST.ASTStmt:
        return stmt

    def transform_goto_stmt(self, stmt: AST.ASTGoto) -> AST.ASTStmt:
        return stmt

    def transform_switch_stmt(self, stmt: AST.ASTSwitchStmt) -> AST.ASTStmt:
        return stmt

    def transform_label(self, label: AST.ASTLabel) -> AST.ASTStmtLabel:
        return label

    def transform_case_label(self, label: AST.ASTCaseLabel) -> AST.ASTStmtLabel:
        return label

    def transform_case_range_label(
            self, label: AST.ASTCaseRangeLabel) -> AST.ASTStmtLabel:
        return label

    def transform_default_label(
            self, label: AST.ASTDefaultLabel) -> AST.ASTStmtLabel:
        return label

    def transform_assign_instr(self, instr: AST.ASTAssign) -> AST.ASTInstruction:
        return instr

    def transform_call_instr(self, instr: AST.ASTCall) -> AST.ASTInstruction:
        return instr

    def transform_lval(self, lval: AST.ASTLval) -> AST.ASTLval:
        return lval

    def transform_varinfo(self, vinfo: AST.ASTVarInfo) -> AST.ASTVarInfo:
        return vinfo

    def transform_variable(self, lhost: AST.ASTVariable) -> AST.ASTLHost:
        return lhost

    def transform_memref(self, lhost: AST.ASTMemRef) -> AST.ASTLHost:
        return lhost

    def transform_no_offset(self, offset: AST.ASTNoOffset) -> AST.ASTOffset:
        return offset

    def transform_field_offset(
            self, offset: AST.ASTFieldOffset) -> AST.ASTOffset:
        return offset

    def transform_index_offset(
            self, offset: AST.ASTIndexOffset) -> AST.ASTOffset:
        return offset

    def transform_integer_constant(
            self, expr: AST.ASTIntegerConstant) -> AST.ASTExpr:
        return expr

    def transform_global_address(
            self, expr: AST.ASTGlobalAddressConstant) -> AST.ASTExpr:
        return expr

    def transform_string_constant(
            self, expr: AST.ASTStringConstant) -> AST.ASTExpr:
        return expr

    def transform_lval_expression(self, expr: AST.ASTLvalExpr) -> AST.ASTExpr:
        return expr

    def transform_sizeof_expression(self, expr: AST.ASTSizeOfExpr) -> AST.ASTExpr:
        return expr

    def transform_cast_expression(self, expr: AST.ASTCastExpr) -> AST.ASTExpr:
        return expr

    def transform_unary_expression(self, expr: AST.ASTUnaryOp) -> AST.ASTExpr:
        return expr

    def transform_binary_expression(self, expr: AST.ASTBinaryOp) -> AST.ASTExpr:
        return expr

    def transform_question_expression(self, expr: AST.ASTQuestion) -> AST.ASTExpr:
        return expr

    def transform_address_of_expression(self, expr: AST.ASTAddressOf) -> AST.ASTExpr:
        return expr

    def transform_void_typ(self, typ: AST.ASTTypVoid) -> AST.ASTTyp:
        return typ

    def transform_integer_typ(self, typ: AST.ASTTypInt) -> AST.ASTTyp:
        return typ

    def transform_float_typ(self, typ: AST.ASTTypFloat) -> AST.ASTTyp:
        return typ

    def transform_pointer_typ(self, typ: AST.ASTTypPtr) -> AST.ASTTyp:
        return typ

    def transform_array_typ(self, typ: AST.ASTTypArray) -> AST.ASTTyp:
        return typ

    def transform_fun_typ(self, typ: AST.ASTTypFun) -> AST.ASTTyp:
        return typ

    def transform_funargs(self, funargs: AST.ASTFunArgs) -> AST.ASTFunArgs:
        return funargs

    def transform_funarg(self, funarg: AST.ASTFunArg) -> AST.ASTFunArg:
        return funarg

    def transform_named_typ(self, typ: AST.ASTTypNamed) -> AST.ASTTyp:
        return typ

    def transform_builtin_va_list(
            self, typ: AST.ASTTypBuiltinVAList) -> AST.ASTTypBuiltinVAList:
        return typ

    def transform_fieldinfo(self, finfo: AST.ASTFieldInfo) -> AST.ASTFieldInfo:
        return finfo

    def transform_compinfo(self, cinfo: AST.ASTCompInfo) -> AST.ASTCompInfo:
        return cinfo

    def transform_comp_typ(self, typ: AST.ASTTypComp) -> AST.ASTTyp:
        return typ

    def transform_enumitem(self, eitem: AST.ASTEnumItem) -> AST.ASTEnumItem:
        return eitem

    def transform_enuminfo(self, einfo: AST.ASTEnumInfo) -> AST.ASTEnumInfo:
        return einfo

    def transform_enum_typ(self, typ: AST.ASTTypEnum) -> AST.ASTTyp:
        return typ
