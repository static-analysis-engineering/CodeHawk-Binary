# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2023  Aarno Labs LLC
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
"""Abstract super class for converters of BC types to AST types."""

from abc import ABC, abstractmethod

from typing import TYPE_CHECKING

import chb.ast.ASTNode as AST

if TYPE_CHECKING:
    from chb.bctypes.BCCompInfo import BCCompInfo
    import chb.bctypes.BCConstant as BCC
    from chb.bctypes.BCEnumInfo import BCEnumInfo
    from chb.bctypes.BCEnumItem import BCEnumItem
    import chb.bctypes.BCExp as BCE
    from chb.bctypes.BCFieldInfo import BCFieldInfo
    from chb.bctypes.BCFunArgs import BCFunArgs, BCFunArg
    from chb.bctypes.BCLHost import BCHostVar, BCHostMem
    from chb.bctypes.BCLval import BCLval
    from chb.bctypes.BCOffset import BCNoOffset, BCFieldOffset, BCIndexOffset
    import chb.bctypes.BCTyp as BCT
    from chb.bctypes.BCVarInfo import BCVarInfo


class BCConverter(ABC):

    def __init__(self) -> None:
        pass

    @abstractmethod
    def convert_lval(self, lval: "BCLval") -> AST.ASTLval:
        ...

    @abstractmethod
    def convert_varinfo(self, vinfo: "BCVarInfo") -> AST.ASTVarInfo:
        ...

    @abstractmethod
    def convert_variable(self, var: "BCHostVar") -> AST.ASTVariable:
        ...

    @abstractmethod
    def convert_memref(self, memref: "BCHostMem") -> AST.ASTMemRef:
        ...

    @abstractmethod
    def convert_no_offset(self, offset: "BCNoOffset") -> AST.ASTNoOffset:
        ...

    @abstractmethod
    def convert_field_offset(
            self, offset: "BCFieldOffset") -> AST.ASTFieldOffset:
        ...

    @abstractmethod
    def convert_index_offset(
            self, offset: "BCIndexOffset") -> AST.ASTIndexOffset:
        ...

    @abstractmethod
    def convert_integer_constant(
            self, c: "BCC.BCCInt64") -> AST.ASTIntegerConstant:
        ...

    @abstractmethod
    def convert_string_constant(self, c: "BCC.BCStr") -> AST.ASTStringConstant:
        ...

    @abstractmethod
    def convert_lval_expression(self, expr: "BCE.BCExpLval") -> AST.ASTLvalExpr:
        ...

    @abstractmethod
    def convert_sizeof_expression(
            self, expr: "BCE.BCExpSizeOf") -> AST.ASTSizeOfExpr:
        ...

    @abstractmethod
    def convert_cast_expression(self, expr: "BCE.BCExpCastE") -> AST.ASTCastExpr:
        ...

    @abstractmethod
    def convert_unary_expression(self, expr: "BCE.BCExpUnOp") -> AST.ASTUnaryOp:
        ...

    @abstractmethod
    def convert_binary_expression(
            self, expr: "BCE.BCExpBinOp") -> AST.ASTBinaryOp:
        ...

    @abstractmethod
    def convert_question_expression(
            self, expr: "BCE.BCExpQuestion") -> AST.ASTQuestion:
        ...

    @abstractmethod
    def convert_address_of_expression(
            self, expr: "BCE.BCExpAddressOf") -> AST.ASTAddressOf:
        ...

    @abstractmethod
    def convert_void_typ(self, t: "BCT.BCTypVoid") -> AST.ASTTypVoid:
        ...

    @abstractmethod
    def convert_integer_typ(self, t: "BCT.BCTypInt") -> AST.ASTTypInt:
        ...

    @abstractmethod
    def convert_float_typ(self, t: "BCT.BCTypFloat") -> AST.ASTTypFloat:
        ...

    @abstractmethod
    def convert_pointer_typ(self, t: "BCT.BCTypPtr") -> AST.ASTTypPtr:
        ...

    @abstractmethod
    def convert_array_typ(self, t: "BCT.BCTypArray") -> AST.ASTTypArray:
        ...

    @abstractmethod
    def convert_fun_typ(self, t: "BCT.BCTypFun") -> AST.ASTTypFun:
        ...

    @abstractmethod
    def convert_funargs(self, t: "BCFunArgs") -> AST.ASTFunArgs:
        ...

    @abstractmethod
    def convert_funarg(self, t: "BCFunArg") -> AST.ASTFunArg:
        ...

    @abstractmethod
    def convert_named_typ(self, t: "BCT.BCTypNamed") -> AST.ASTTypNamed:
        ...

    @abstractmethod
    def convert_builtin_va_list(
            self, t: "BCT.BCTypBuiltinVaList") -> AST.ASTTypBuiltinVAList:
        ...

    @abstractmethod
    def convert_comp_typ(self, t: "BCT.BCTypComp") -> AST.ASTTypComp:
        ...

    @abstractmethod
    def convert_compinfo(self, cinfo: "BCCompInfo") -> AST.ASTCompInfo:
        ...

    @abstractmethod
    def convert_fieldinfo(self, finfo: "BCFieldInfo") -> AST.ASTFieldInfo:
        ...

    @abstractmethod
    def convert_enum_typ(self, t: "BCT.BCTypEnum") -> AST.ASTTypEnum:
        ...

    @abstractmethod
    def convert_enuminfo(self, einfo: "BCEnumInfo") -> AST.ASTEnumInfo:
        ...

    @abstractmethod
    def convert_enumitem(self, eitem: "BCEnumItem") -> AST.ASTEnumItem:
        ...
