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

from typing import cast, List, TYPE_CHECKING

import chb.ast.ASTNode as AST

from chb.bctypes.BCConverter import BCConverter
from chb.bctypes.BCDictionaryRecord import BCDictionaryRecord
from chb.bctypes.BCVisitor import BCVisitor

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCTyp import BCTyp, BCTypComp, BCTypArray


class BCFunArg(BCDictionaryRecord):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCDictionaryRecord.__init__(self, bcd, ixval)

    @property
    def name(self) -> str:
        return self.tags[0]

    @property
    def typ(self) -> "BCTyp":
        return self.bcd.typ(self.args[0])

    def is_leq(self, other: "BCFunArg") -> bool:
        return self.typ.is_leq(other.typ)

    def convert(self, converter: "BCConverter") -> AST.ASTFunArg:
        return converter.convert_funarg(self)

    def __str__(self) -> str:
        return str(self.typ) + " " + self.name


class BCStructFieldFunArg(BCFunArg):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue,
            name: str,
            typ: "BCTyp") -> None:
        BCFunArg.__init__(self, bcd, ixval)
        self._name = name
        self._typ = typ

    @property
    def name(self) -> str:
        return self._name

    @property
    def typ(self) -> "BCTyp":
        return self._typ


class BCFunArgs(BCDictionaryRecord):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCDictionaryRecord.__init__(self, cd, ixval)

    @property
    def funargs(self) -> List["BCFunArg"]:
        return [self.bcd.funarg(i) for i in self.args]

    @property
    def argtypes(self) -> List["BCTyp"]:
        return [a.typ for a in self.funargs]

    @property
    def is_scalar_argtypes(self) -> bool:
        for t in self.argtypes:
            if not t.is_scalar:
                return False
        else:
            return True

    def is_leq(self, other: "BCFunArgs") -> bool:
        return all(a.is_leq(o) for (a, o) in zip(self.funargs, other.funargs))

    def convert(self, converter: "BCConverter") -> AST.ASTFunArgs:
        return converter.convert_funargs(self)

    def __str__(self) -> str:
        return "(" + ", ".join(str(a) for a in self.funargs) + ")"
