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
"""Abstract super class for visitors of BC types."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from chb.bctypes.BCCompInfo import BCCompInfo
    import chb.bctypes.BCConstant as BCC
    import chb.bctypes.BCExp as BCE
    from chb.bctypes.BCFieldInfo import BCFieldInfo
    from chb.bctypes.BCFunArgs import BCFunArgs, BCFunArg
    from chb.bctypes.BCLHost import BCHostVar, BCHostMem
    from chb.bctypes.BCLval import BCLval
    from chb.bctypes.BCOffset import BCNoOffset, BCFieldOffset, BCIndexOffset
    import chb.bctypes.BCTyp as BCT
    from chb.bctypes.BCVarInfo import BCVarInfo


class BCVisitor(ABC):

    def __init__(self) -> None:
        pass

    @abstractmethod
    def visit_lval(self, lval: "BCLval") -> None:
        ...

    @abstractmethod
    def visit_varinfo(self, vinfo: "BCVarInfo") -> None:
        ...

    @abstractmethod
    def visit_variable(self, var: "BCHostVar") -> None:
        ...

    @abstractmethod
    def visit_memref(self, memref: "BCHostMem") -> None:
        ...

    @abstractmethod
    def visit_no_offset(self, offset: "BCNoOffset") -> None:
        ...

    @abstractmethod
    def visit_field_offset(self, offset: "BCFieldOffset") -> None:
        ...

    @abstractmethod
    def visit_index_offset(self, offset: "BCIndexOffset") -> None:
        ...

    @abstractmethod
    def visit_integer_constant(self, c: "BCC.BCCInt64") -> None:
        ...

    @abstractmethod
    def visit_string_constant(self, c: "BCC.BCStr") -> None:
        ...

    @abstractmethod
    def visit_lval_expression(self, expr: "BCE.BCExpLval") -> None:
        ...

    @abstractmethod
    def visit_cast_expression(self, expr: "BCE.BCExpCastE") -> None:
        ...

    @abstractmethod
    def visit_unary_expression(self, expr: "BCE.BCExpUnOp") -> None:
        ...

    @abstractmethod
    def visit_binary_expression(self, expr: "BCE.BCExpBinOp") -> None:
        ...

    @abstractmethod
    def visit_question_expression(self, expr: "BCE.BCExpQuestion") -> None:
        ...

    @abstractmethod
    def visit_address_of_expression(self, expr: "BCE.BCExpAddressOf") -> None:
        ...

    @abstractmethod
    def visit_void_typ(self, typ: "BCT.BCTypVoid") -> None:
        ...

    @abstractmethod
    def visit_integer_typ(self, typ: "BCT.BCTypInt") -> None:
        ...

    @abstractmethod
    def visit_float_typ(self, typ: "BCT.BCTypFloat") -> None:
        ...

    @abstractmethod
    def visit_pointer_typ(self, typ: "BCT.BCTypPtr") -> None:
        ...

    @abstractmethod
    def visit_array_typ(self, typ: "BCT.BCTypArray") -> None:
        ...

    @abstractmethod
    def visit_fun_typ(self, typ: "BCT.BCTypFun") -> None:
        ...

    @abstractmethod
    def visit_funargs(self, funargs: "BCFunArgs") -> None:
        ...

    @abstractmethod
    def visit_funarg(self, funarg: "BCFunArg") -> None:
        ...

    @abstractmethod
    def visit_named_typ(self, typ: "BCT.BCTypNamed") -> None:
        ...
