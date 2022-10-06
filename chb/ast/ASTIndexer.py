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
"""Abstract class for AST serializers that assign some index to ast nodes."""

from abc import ABC, abstractmethod

import chb.ast.ASTNode as AST


class ASTIndexer(ABC):

    def __init__(self) -> None:
        pass

    @abstractmethod
    def index_return_stmt(self, stmt: AST.ASTReturn) -> int:
        ...

    @abstractmethod
    def index_break_stmt(self, stmt: AST.ASTBreak) -> int:
        ...

    @abstractmethod
    def index_continue_stmt(self, stmt: AST.ASTContinue) -> int:
        ...

    @abstractmethod
    def index_loop_stmt(self, stmt: AST.ASTLoop) -> int:
        ...

    @abstractmethod
    def index_block_stmt(self, stmt: AST.ASTBlock) -> int:
        ...

    @abstractmethod
    def index_instruction_sequence_stmt(self, stmt: AST.ASTInstrSequence) -> int:
        ...

    @abstractmethod
    def index_branch_stmt(self, stmt: AST.ASTBranch) -> int:
        ...

    @abstractmethod
    def index_goto_stmt(self, stmt: AST.ASTGoto) -> int:
        ...

    @abstractmethod
    def index_switch_stmt(self, stmt: AST.ASTSwitchStmt) -> int:
        ...

    @abstractmethod
    def index_label(self, label: AST.ASTLabel) -> int:
        ...

    @abstractmethod
    def index_case_label(self, label: AST.ASTCaseLabel) -> int:
        ...

    @abstractmethod
    def index_case_range_label(self, label: AST.ASTCaseRangeLabel) -> int:
        ...

    @abstractmethod
    def index_default_label(self, label: AST.ASTDefaultLabel) -> int:
        ...

    @abstractmethod
    def index_assign_instr(self, instr: AST.ASTAssign) -> int:
        ...

    @abstractmethod
    def index_call_instr(self, instr: AST.ASTCall) -> int:
        ...

    @abstractmethod
    def index_lval(self, lval: AST.ASTLval) -> int:
        ...

    @abstractmethod
    def index_varinfo(self, vinfo: AST.ASTVarInfo) -> int:
        ...

    @abstractmethod
    def index_variable(self, var: AST.ASTVariable) -> int:
        ...

    @abstractmethod
    def index_memref(self, memref: AST.ASTMemRef) -> int:
        ...

    @abstractmethod
    def index_no_offset(self, offset: AST.ASTNoOffset) -> int:
        ...

    @abstractmethod
    def index_field_offset(self, offset: AST.ASTFieldOffset) -> int:
        ...

    @abstractmethod
    def index_index_offset(self, offset: AST.ASTIndexOffset) -> int:
        ...

    @abstractmethod
    def index_integer_constant(self, const: AST.ASTIntegerConstant) -> int:
        ...

    @abstractmethod
    def index_global_address(self, addr: AST.ASTGlobalAddressConstant) -> int:
        ...

    @abstractmethod
    def index_string_constant(self, strc: AST.ASTStringConstant) -> int:
        ...

    @abstractmethod
    def index_lval_expression(self, expr: AST.ASTLvalExpr) -> int:
        ...

    @abstractmethod
    def index_sizeof_expression(self, expr: AST.ASTSizeOfExpr) -> int:
        ...

    @abstractmethod
    def index_cast_expression(self, expr: AST.ASTCastExpr) -> int:
        ...

    @abstractmethod
    def index_unary_expression(self, expr: AST.ASTUnaryOp) -> int:
        ...

    @abstractmethod
    def index_binary_expression(self, expr: AST.ASTBinaryOp) -> int:
        ...

    @abstractmethod
    def index_question_expression(self, expr: AST.ASTQuestion) -> int:
        ...

    @abstractmethod
    def index_address_of_expression(self, expr: AST.ASTAddressOf) -> int:
        ...

    @abstractmethod
    def index_void_typ(self, typ: AST.ASTTypVoid) -> int:
        ...

    @abstractmethod
    def index_integer_typ(self, typ: AST.ASTTypInt) -> int:
        ...

    @abstractmethod
    def index_float_typ(self, typ: AST.ASTTypFloat) -> int:
        ...

    @abstractmethod
    def index_pointer_typ(self, typ: AST.ASTTypPtr) -> int:
        ...

    @abstractmethod
    def index_array_typ(self, typ: AST.ASTTypArray) -> int:
        ...

    @abstractmethod
    def index_fun_typ(self, typ: AST.ASTTypFun) -> int:
        ...

    @abstractmethod
    def index_funargs(self, funargs: AST.ASTFunArgs) -> int:
        ...

    @abstractmethod
    def index_funarg(self, funarg: AST.ASTFunArg) -> int:
        ...

    @abstractmethod
    def index_named_typ(self, typ: AST.ASTTypNamed) -> int:
        ...

    @abstractmethod
    def index_builtin_va_list(self, typ: AST.ASTTypBuiltinVAList) -> int:
        ...

    @abstractmethod
    def index_fieldinfo(self, finfo: AST.ASTFieldInfo) -> int:
        ...

    @abstractmethod
    def index_compinfo(self, cinfo: AST.ASTCompInfo) -> int:
        ...

    @abstractmethod
    def index_comp_typ(self, typ: AST.ASTTypComp) -> int:
        ...

    @abstractmethod
    def index_enumitem(self, eitem: AST.ASTEnumItem) -> int:
        ...

    @abstractmethod
    def index_enuminfo(self, einfo: AST.ASTEnumInfo) -> int:
        ...

    @abstractmethod
    def index_enum_typ(self, typ: AST.ASTTypEnum) -> int:
        ...
