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
"""Abstract super class for visitors on ASTNodes. """


from abc import ABC, abstractmethod

import chb.ast.ASTNode as AST


class ASTVisitor(ABC):

    def __init__(self) -> None:
        pass

    @abstractmethod
    def visit_return_stmt(self, stmt: AST.ASTReturn) -> None:
        ...

    @abstractmethod
    def visit_break_stmt(self, stmt: AST.ASTBreak) -> None:
        ...

    @abstractmethod
    def visit_continue_stmt(self, stmt: AST.ASTContinue) -> None:
        ...

    @abstractmethod
    def visit_loop_stmt(self, stmt: AST.ASTLoop) -> None:
        ...

    @abstractmethod
    def visit_block_stmt(self, stmt: AST.ASTBlock) -> None:
        ...

    @abstractmethod
    def visit_instruction_sequence_stmt(
            self, stmt: AST.ASTInstrSequence) -> None:
        ...

    @abstractmethod
    def visit_branch_stmt(self, stmt: AST.ASTBranch) -> None:
        ...

    @abstractmethod
    def visit_goto_stmt(self, stmt: AST.ASTGoto) -> None:
        ...

    @abstractmethod
    def visit_switch_stmt(self, stmt: AST.ASTSwitchStmt) -> None:
        ...

    @abstractmethod
    def visit_label(self, label: AST.ASTLabel) -> None:
        ...

    @abstractmethod
    def visit_case_label(self, label: AST.ASTCaseLabel) -> None:
        ...

    @abstractmethod
    def visit_case_range_label(self, label: AST.ASTCaseRangeLabel) -> None:
        ...

    @abstractmethod
    def visit_default_label(self, label: AST.ASTDefaultLabel) -> None:
        ...

    @abstractmethod
    def visit_assign_instr(self, instr: AST.ASTAssign) -> None:
        ...

    @abstractmethod
    def visit_call_instr(self, instr: AST.ASTCall) -> None:
        ...

    @abstractmethod
    def visit_lval(self, lval: AST.ASTLval) -> None:
        ...

    @abstractmethod
    def visit_varinfo(self, vinfo: AST.ASTVarInfo) -> None:
        ...

    @abstractmethod
    def visit_variable(self, var: AST.ASTVariable) -> None:
        ...

    @abstractmethod
    def visit_memref(self, memref: AST.ASTMemRef) -> None:
        ...

    @abstractmethod
    def visit_no_offset(self, offset: AST.ASTNoOffset) -> None:
        ...

    @abstractmethod
    def visit_field_offset(self, offset: AST.ASTFieldOffset) -> None:
        ...

    @abstractmethod
    def visit_index_offset(self, offset: AST.ASTIndexOffset) -> None:
        ...

    @abstractmethod
    def visit_integer_constant(
            self, intconstant: AST.ASTIntegerConstant) -> None:
        ...

    @abstractmethod
    def visit_global_address(
            self, globalddress: AST.ASTGlobalAddressConstant) -> None:
        ...

    @abstractmethod
    def visit_string_constant(
            self, stringconstant: AST.ASTStringConstant) -> None:
        ...

    @abstractmethod
    def visit_lval_expression(self, expr: AST.ASTLvalExpr) -> None:
        ...

    @abstractmethod
    def visit_sizeof_expression(self, expr: AST.ASTSizeOfExpr) -> None:
        ...

    @abstractmethod
    def visit_cast_expression(self, expr: AST.ASTCastExpr) -> None:
        ...

    @abstractmethod
    def visit_unary_expression(self, expr: AST.ASTUnaryOp) -> None:
        ...

    @abstractmethod
    def visit_binary_expression(self, expr: AST.ASTBinaryOp) -> None:
        ...

    @abstractmethod
    def visit_question_expression(self, expr: AST.ASTQuestion) -> None:
        ...

    @abstractmethod
    def visit_address_of_expression(self, expr: AST.ASTAddressOf) -> None:
        ...

    @abstractmethod
    def visit_void_typ(self, typ: AST.ASTTypVoid) -> None:
        ...

    @abstractmethod
    def visit_integer_typ(self, typ: AST.ASTTypInt) -> None:
        ...

    @abstractmethod
    def visit_float_typ(self, typ: AST.ASTTypFloat) -> None:
        ...

    @abstractmethod
    def visit_pointer_typ(self, typ: AST.ASTTypPtr) -> None:
        ...

    @abstractmethod
    def visit_array_typ(self, typ: AST.ASTTypArray) -> None:
        ...

    @abstractmethod
    def visit_fun_typ(self, typ: AST.ASTTypFun) -> None:
        ...

    @abstractmethod
    def visit_funargs(self, funargs: AST.ASTFunArgs) -> None:
        ...

    @abstractmethod
    def visit_funarg(self, funarg: AST.ASTFunArg) -> None:
        ...

    @abstractmethod
    def visit_named_typ(self, typ: AST.ASTTypNamed) -> None:
        ...

    @abstractmethod
    def visit_builtin_va_list(self, typ: AST.ASTTypBuiltinVAList) -> None:
        ...

    @abstractmethod
    def visit_compinfo(self, cinfo: AST.ASTCompInfo) -> None:
        ...

    @abstractmethod
    def visit_fieldinfo(self, finfo: AST.ASTFieldInfo) -> None:
        ...

    @abstractmethod
    def visit_comp_typ(self, typ: AST.ASTTypComp) -> None:
        ...

    @abstractmethod
    def visit_enumitem(self, eitem: AST.ASTEnumItem) -> None:
        ...

    @abstractmethod
    def visit_enuminfo(self, einfo: AST.ASTEnumInfo) -> None:
        ...

    @abstractmethod
    def visit_enum_typ(self, typ: AST.ASTTypEnum) -> None:
        ...
