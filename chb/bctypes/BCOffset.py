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
"""CIL offset.

Corresponds to offset in CIL

                                                          tags[0]  tags   args
type offset
    | NoOffset                                              "n"      1      0
    | Field                                                 "f"      2      2
    | Index                                                 "i"      1      2
"""

from typing import List, TYPE_CHECKING

from chb.bctypes.BCDictionaryRecord import BCDictionaryRecord, bcregistry

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCExp import BCExp


class BCOffset(BCDictionaryRecord):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCDictionaryRecord.__init__(self, cd, ixval)

    def __str__(self) -> str:
        return "bc-offset:" + self.tags[0]


@bcregistry.register_tag("n", BCOffset)
class BCNoOffset(BCOffset):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCOffset.__init__(self, cd, ixval)

    def __str__(self) -> str:
        return ""


@bcregistry.register_tag("f", BCOffset)
class BCFieldOffset(BCOffset):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCOffset.__init__(self, cd, ixval)

    @property
    def fieldname(self) -> str:
        return self.tags[1]

    @property
    def compkey(self) -> int:
        return self.args[0]

    @property
    def suboffset(self) -> "BCOffset":
        return self.bcd.offset(self.args[1])

    def __str__(self) -> str:
        return "." + self.fieldname + str(self.suboffset)


@bcregistry.register_tag("i", BCOffset)
class BCIndexOffset(BCOffset):

    def __init__(
            self,
            cd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCOffset.__init__(self, cd, ixval)

    @property
    def exp(self) -> "BCExp":
        return self.bcd.exp(self.args[0])

    @property
    def suboffset(self) -> "BCOffset":
        return self.bcd.offset(self.args[1])

    def __str__(self) -> str:
        return "[" + str(self.exp) + "]" + str(self.suboffset)
