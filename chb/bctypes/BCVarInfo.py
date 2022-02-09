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

from chb.bctypes.BCDictionaryRecord import BCDictionaryRecord

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCTyp import BCTyp, BCTypArray, BCTypFun


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

    def serialize(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        result["name"] = self.vname
        result["args"] = [self.vtype.index]
        return result

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
            return (str(ftype.returntype) + " " + self.vname + argtypes)
        else:
            return str(self.vtype) + " " + self.vname
