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

from typing import Any, cast, Dict, List, TYPE_CHECKING

import chb.ast.ASTNode as AST

from chb.bctypes.BCConverter import BCConverter
from chb.bctypes.BCDictionaryRecord import BCDictionaryRecord

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.bctypes.BCAttribute import BCAttribute
    from chb.bctypes.BCAttrParam import BCAttrParam, BCAttrParamInt
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCTyp import BCTyp, BCTypArray, BCTypComp


class BCFieldInfo(BCDictionaryRecord):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCDictionaryRecord.__init__(self, bcd, ixval)

    @property
    def fieldname(self) -> str:
        return self.tags[0]

    @property
    def ckey(self) -> int:
        return self.args[0]

    @property
    def fieldtype(self) -> "BCTyp":
        return self.bcd.typ(self.args[1])

    @property
    def attrs(self) -> List["BCAttribute"]:
        attrs = self.bcd.attributes(self.args[3])
        if attrs is None:
            return []
        else:
            return attrs.attrs

    def is_leq(self, other: "BCFieldInfo") -> bool:
        if self.fieldname == other.fieldname:
            return self.fieldtype.is_leq(other.fieldtype)
        else:
            return False

    def byte_size(self) -> int:
        return self.fieldtype.byte_size()

    def alignment(self) -> int:
        if len(self.attrs) > 0:
            for attr in self.attrs:
                if attr.name == "aligned":
                    params = attr.params
                    for param in attr.params:
                        if param.is_int:
                            return cast("BCAttrParamInt", param).intvalue

        return self.fieldtype.alignment()

    def convert(self, converter: BCConverter) -> AST.ASTFieldInfo:
        return converter.convert_fieldinfo(self)

    def __str__(self) -> str:
        if self.fieldtype.is_array:
            ftype = cast("BCTypArray", self.fieldtype)
            if ftype.has_constant_size():
                asize = ftype.sizevalue
                return (
                    str(ftype.tgttyp)
                    + " "
                    + self.fieldname
                    + "["
                    + str(asize)
                    + "];")
        return str(self.fieldtype) + " " + self.fieldname + ";"
