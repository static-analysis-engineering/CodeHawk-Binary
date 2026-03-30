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

from typing import Any, cast, Dict, List, Optional, TYPE_CHECKING

import chb.ast.ASTNode as AST

from chb.bctypes.BCAttribute import BCAttributes
from chb.bctypes.BCConverter import BCConverter
from chb.bctypes.BCDictionaryRecord import BCDictionaryRecord
from chb.bctypes.BCVisitor import BCVisitor

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCTyp import BCTyp, BCTypArray, BCTypFun
    from chb.bctypes.BCVisitor import BCVisitor


class BCVarInfo(BCDictionaryRecord):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCDictionaryRecord.__init__(self, bcd, ixval)

    @property
    def vname(self) -> str:
        return self.tags[0]

    @property
    def vid(self) -> int:
        return self.args[0]

    @property
    def vtype(self) -> "BCTyp":
        return self.bcd.typ(self.args[1])

    @property
    def vparam(self) -> int:
        return self.args[7]

    @property
    def attributes(self) -> Optional["BCAttributes"]:
        return self.bcd.attributes(self.args[2])

    def accept(self, visitor: "BCVisitor") -> None:
        visitor.visit_varinfo(self)

    def convert(self, converter: "BCConverter") -> AST.ASTVarInfo:
        return converter.convert_varinfo(self)

    @property
    def to_c_string(self) -> str:
        if self.vtype.is_array:
            atype = cast("BCTypArray", self.vtype)
            if atype.has_constant_size():
                asize = atype.sizevalue
                return (
                    str(atype.tgttyp)
                    + " "
                    + self.vname
                    + "["
                    + str(asize)
                    + "];")
            else:
                return str(self.vtype) + " " + self.vname
        elif self.vtype.is_function:
            ftype = cast("BCTypFun", self.vtype)
            if ftype.argtypes is not None:
                argtypes = str(ftype.argtypes)
            else:
                argtypes = "()"
            fattrs = self.attributes
            if fattrs is not None and not fattrs.is_empty:
                pfattrs = "\n" + fattrs.to_c_string
            else:
                pfattrs = ""
            return (
                str(ftype.returntype)
                + " "
                + self.vname
                + argtypes
                + pfattrs
                + ";")
        else:
            return str(self.vtype) + " " + self.vname + ";"


    def __str__(self) -> str:
        if self.vtype.is_array:
            atype = cast("BCTypArray", self.vtype)
            if atype.has_constant_size():
                asize = atype.sizevalue
                return (
                    str(atype.tgttyp)
                    + " "
                    + self.vname
                    + "["
                    + str(asize)
                    + "];")
            else:
                return str(self.vtype) + " " + self.vname
        elif self.vtype.is_function:
            ftype = cast("BCTypFun", self.vtype)
            if ftype.argtypes is not None:
                argtypes = str(ftype.argtypes)
            else:
                argtypes = "()"
            fattrs = self.attributes
            if fattrs is not None:
                pfattrs = " " + str(fattrs)
            else:
                pfattrs = ""
            return (str(ftype.returntype) + " " + self.vname + argtypes + pfattrs)
        else:
            return str(self.vtype) + " " + self.vname
