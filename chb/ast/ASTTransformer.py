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
"""Abstract class for AST transformers that transform nodes into the same type."""

from abc import ABC, abstractmethod

import chb.ast.ASTNode as AST


class ASTTransformer(ABC):

    def __init__(self) -> None:
        pass

    @abstractmethod
    def transform_return_stmt(self, stmt: AST.ASTReturn) -> AST.ASTStmt:
        ...

    @abstractmethod
    def transform_break_stmt(self, stmt: AST.ASTBreak) -> AST.ASTStmt:
        ...

    @abstractmethod
    def transform_continue_stmt(self, stmt: AST.ASTContinue) -> AST.ASTStmt:
        ...

    @abstractmethod
    def transform_loop_stmt(self, stmt: AST.ASTLoop) -> AST.ASTStmt:
        ...

    @abstractmethod
    def transform_block_stmt(self, stmt: AST.ASTBlock) -> AST.ASTStmt:
        ...

    @abstractmethod
    def transform_instruction_sequence_stmt(
            self, stmt: AST.ASTInstrSequence) -> AST.ASTStmt:
        ...

    @abstractmethod
    def transform_branch_stmt(self, stmt: AST.ASTBranch) -> AST.ASTStmt:
        ...

    @abstractmethod
    def transform_goto_stmt(self, stmt: AST.ASTGoto) -> AST.ASTStmt:
        ...

    @abstractmethod
    def transform_switch_stmt(self, stmt: AST.ASTSwitchStmt) -> AST.ASTStmt:
        ...

    @abstractmethod
    def transform_label(self, label: AST.ASTLabel) -> AST.ASTStmtLabel:
        ...

    @abstractmethod
    def transform_case_label(self, label: AST.ASTCaseLabel) -> AST.ASTStmtLabel:
        ...

    @abstractmethod
    def transform_case_range_label(
            self, label: AST.ASTCaseRangeLabel) -> AST.ASTStmtLabel:
        ...

    @abstractmethod
    def transform_default_label(
            self, label: AST.ASTDefaultLabel) -> AST.ASTStmtLabel:
        ...

    @abstractmethod
    def transform_assign_instr(self, instr: AST.ASTAssign) -> AST.ASTInstruction:
        ...

    @abstractmethod
    def transform_call_instr(self, instr: AST.ASTCall) -> AST.ASTInstruction:
        ...

    @abstractmethod
    def transform_lval(self, lval: AST.ASTLval) -> AST.ASTLval:
        ...

    @abstractmethod
    def transform_varinfo(self, vinfo: AST.ASTVarInfo) -> AST.ASTVarInfo:
        ...

    @abstractmethod
    def transform_variable(self, lhost: AST.ASTVariable) -> AST.ASTLHost:
        ...

    @abstractmethod
    def transform_memref(self, lhost: AST.ASTMemRef) -> AST.ASTLHost:
        ...

    @abstractmethod
    def transform_no_offset(self, offset: AST.ASTNoOffset) -> AST.ASTOffset:
        ...

    @abstractmethod
    def transform_field_offset(
            self, offset: AST.ASTFieldOffset) -> AST.ASTOffset:
        ...

    @abstractmethod
    def transform_index_offset(
            self, offset: AST.ASTIndexOffset) -> AST.ASTOffset:
        ...

    @abstractmethod
    def transform_integer_constant(
            self, intconstant: AST.ASTIntegerConstant) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_global_address(
            self, globaladdr: AST.ASTGlobalAddressConstant) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_string_constant(
            self, stringconstant: AST.ASTStringConstant) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_lval_expression(self, expr: AST.ASTLvalExpr) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_sizeof_expression(self, expr: AST.ASTSizeOfExpr) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_cast_expression(self, expr: AST.ASTCastExpr) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_unary_expression(self, expr: AST.ASTUnaryOp) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_binary_expression(self, expr: AST.ASTBinaryOp) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_question_expression(self, expr: AST.ASTQuestion) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_address_of_expression(self, expr: AST.ASTAddressOf) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_void_typ(self, typ: AST.ASTTypVoid) -> AST.ASTTyp:
        ...

    @abstractmethod
    def transform_integer_typ(self, typ: AST.ASTTypInt) -> AST.ASTTyp:
        ...

    @abstractmethod
    def transform_float_typ(self, typ: AST.ASTTypFloat) -> AST.ASTTyp:
        ...

    @abstractmethod
    def transform_pointer_typ(self, typ: AST.ASTTypPtr) -> AST.ASTTyp:
        ...

    @abstractmethod
    def transform_array_typ(self, typ: AST.ASTTypArray) -> AST.ASTTyp:
        ...

    @abstractmethod
    def transform_fun_typ(self, typ: AST.ASTTypFun) -> AST.ASTTyp:
        ...

    @abstractmethod
    def transform_funargs(self, funargs: AST.ASTFunArgs) -> AST.ASTFunArgs:
        ...

    @abstractmethod
    def transform_funarg(self, funarg: AST.ASTFunArg) -> AST.ASTFunArg:
        ...

    @abstractmethod
    def transform_named_typ(self, typ: AST.ASTTypNamed) -> AST.ASTTyp:
        ...

    @abstractmethod
    def transform_builtin_va_list(
            self, typ: AST.ASTTypBuiltinVAList) -> AST.ASTTypBuiltinVAList:
        ...

    @abstractmethod
    def transform_fieldinfo(self, finfo: AST.ASTFieldInfo) -> AST.ASTFieldInfo:
        ...

    @abstractmethod
    def transform_compinfo(self, cinfo: AST.ASTCompInfo) -> AST.ASTCompInfo:
        ...

    @abstractmethod
    def transform_comp_typ(self, typ: AST.ASTTypComp) -> AST.ASTTyp:
        ...
