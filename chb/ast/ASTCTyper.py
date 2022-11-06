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
"""Abstract class that attempts to provide C typing for an AST."""

from abc import ABC, abstractmethod

from typing import Optional

import chb.ast.ASTNode as AST


class ASTCTyper(ABC):

    def __init__(self) -> None:
        pass

    def ctype_return_stmt(self, stmt: AST.ASTReturn) -> Optional[AST.ASTTyp]:
        return None

    def ctype_break_stmt(self, stmt: AST.ASTBreak) -> Optional[AST.ASTTyp]:
        return None

    def ctype_continue_stmt(self, stmt: AST.ASTContinue) -> Optional[AST.ASTTyp]:
        return None

    def ctype_loop_stmt(self, stmt: AST.ASTLoop) -> Optional[AST.ASTTyp]:
        return None

    def ctype_block_stmt(self, stmt: AST.ASTBlock) -> Optional[AST.ASTTyp]:
        return None

    def ctype_instruction_sequence_stmt(
            self, stmt: AST.ASTInstrSequence) -> Optional[AST.ASTTyp]:
        return None

    def ctype_branch_stmt(self, stmt: AST.ASTBranch) -> Optional[AST.ASTTyp]:
        return None

    def ctype_goto_stmt(self, stmt: AST.ASTGoto) -> Optional[AST.ASTTyp]:
        return None

    def ctype_computedgoto_stmt(
            self, stmt: AST.ASTComputedGoto) -> Optional[AST.ASTTyp]:
        return None

    def ctype_switch_stmt(self, stmt: AST.ASTSwitchStmt) -> Optional[AST.ASTTyp]:
        return None

    def ctype_label(self, label: AST.ASTLabel) -> Optional[AST.ASTTyp]:
        return None

    def ctype_case_label(self, label: AST.ASTCaseLabel) -> Optional[AST.ASTTyp]:
        return None

    def ctype_case_range_label(
            self, label: AST.ASTCaseRangeLabel) -> Optional[AST.ASTTyp]:
        return None

    def ctype_default_label(
            self, label: AST.ASTDefaultLabel) -> Optional[AST.ASTTyp]:
        return None

    def ctype_assign_instr(self, instr: AST.ASTAssign) -> Optional[AST.ASTTyp]:
        return None

    def ctype_call_instr(self, instr: AST.ASTCall) -> Optional[AST.ASTTyp]:
        return None

    @abstractmethod
    def ctype_lval(self, lval: AST.ASTLval) -> Optional[AST.ASTTyp]:
        ...

    def ctype_varinfo(self, vinfo: AST.ASTVarInfo) -> Optional[AST.ASTTyp]:
        return vinfo.vtype

    @abstractmethod
    def ctype_variable(self, var: AST.ASTVariable) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_memref(self, memref: AST.ASTMemRef) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_no_offset(self, offset: AST.ASTNoOffset) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_field_offset(
            self, offset: AST.ASTFieldOffset) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_index_offset(
            self, offset: AST.ASTIndexOffset) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_integer_constant(
            self, const: AST.ASTIntegerConstant) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_floating_point_constant(
            self, fp: AST.ASTFloatingPointConstant) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_global_address(
            self, addr: AST.ASTGlobalAddressConstant) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_string_constant(
            self, strc: AST.ASTStringConstant) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_lval_expression(
            self, expr: AST.ASTLvalExpr) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_sizeof_expression(
            self, expr: AST.ASTSizeOfExpr) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_cast_expression(
            self, expr: AST.ASTCastExpr) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_unary_expression(
            self, expr: AST.ASTUnaryOp) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_binary_expression(
            self, expr: AST.ASTBinaryOp) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_question_expression(
            self, expr: AST.ASTQuestion) -> Optional[AST.ASTTyp]:
        ...

    @abstractmethod
    def ctype_address_of_expression(
            self, expr: AST.ASTAddressOf) -> Optional[AST.ASTTyp]:
        ...

    def ctype_void_typ(self, typ: AST.ASTTypVoid) -> Optional[AST.ASTTyp]:
        return typ

    def ctype_integer_typ(self, typ: AST.ASTTypInt) -> Optional[AST.ASTTyp]:
        return typ

    def ctype_float_typ(self, typ: AST.ASTTypFloat) -> Optional[AST.ASTTyp]:
        return typ

    def ctype_pointer_typ(self, typ: AST.ASTTypPtr) -> Optional[AST.ASTTyp]:
        return typ

    def ctype_array_typ(self, typ: AST.ASTTypArray) -> Optional[AST.ASTTyp]:
        return typ

    def ctype_fun_typ(self, typ: AST.ASTTypFun) -> Optional[AST.ASTTyp]:
        return typ

    def ctype_funargs(self, funargs: AST.ASTFunArgs) -> Optional[AST.ASTTyp]:
        return None

    def ctype_funarg(self, funarg: AST.ASTFunArg) -> Optional[AST.ASTTyp]:
        return funarg.argtyp

    def ctype_named_typ(self, typ: AST.ASTTypNamed) -> Optional[AST.ASTTyp]:
        return typ.typdef

    def ctype_builtin_va_list(
            self, typ: AST.ASTTypBuiltinVAList) -> Optional[AST.ASTTyp]:
        return typ

    @abstractmethod
    def ctype_fieldinfo(self, finfo: AST.ASTFieldInfo) -> Optional[AST.ASTTyp]:
        ...

    def ctype_compinfo(self, cinfo: AST.ASTCompInfo) -> Optional[AST.ASTTyp]:
        return None

    def ctype_comp_typ(self, typ: AST.ASTTypComp) -> Optional[AST.ASTTyp]:
        return typ

    def ctype_enuminfo(self, einfo: AST.ASTEnumInfo) -> Optional[AST.ASTTyp]:
        return None

    def ctype_enumitem(self, eitem: AST.ASTEnumItem) -> Optional[AST.ASTTyp]:
        return None

    def ctype_enum_typ(self, typ: AST.ASTTypEnum) -> Optional[AST.ASTTyp]:
        return typ
