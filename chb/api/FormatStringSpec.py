# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2026  Aarno Labs LLC
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

from dataclasses import dataclass
from typing import List, Optional, TYPE_CHECKING

from chb.api.InterfaceDictionaryRecord import InterfaceDictionaryRecord

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.InterfaceDictionary import InterfaceDictionary


@dataclass
class FmtArgFieldWidth:
    s: str

    def has_fieldwidth(self) -> bool:
        return self.s.startswith("fwc:")

    def has_fieldwidth_argument(self) -> bool:
        return self.s == "fwa"

    def fieldwidth(self) -> Optional[int]:
        if self.has_fieldwidth():
            return int(self.s[4:])
        return None

    def __str__(self) -> str:
        if self.has_fieldwidth():
            return self.s[4:]
        elif self.has_fieldwidth_argument():
            return "*"
        else:
            return ""

@dataclass
class FmtArgPrecision:
    s: str

    def has_precision(self) -> bool:
        return self.s.startswith("pc:")

    def has_precision_argument(self) -> bool:
        return self.s == "pa"

    def precision(self) -> Optional[int]:
        if self.has_precision():
            return int(self.s[3:])
        return None

    def __str__(self) -> str:
        if self.has_precision():
            return "." + self.s[3:]
        elif self.has_precision_argument():
            return ".*"
        else:
            return ""


class FormatArgSpec(InterfaceDictionaryRecord):

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        InterfaceDictionaryRecord.__init__(self, ixd, ixval)

    @property
    def fieldwidth(self) -> FmtArgFieldWidth:
        return FmtArgFieldWidth(self.tags[0])

    @property
    def precision(self) -> FmtArgPrecision:
        return FmtArgPrecision(self.tags[1])

    @property
    def lengthmodifier(self) -> str:
        if self.tags[2] == "none":
            return ""
        else:
            return self.tags[2]

    @property
    def conversion(self) -> str:
        return self.tags[3]

    @property
    def flags(self) -> str:
        return "".join(chr(i) for i in self.args)

    def __str__(self):
        return (
            "%"
            + self.flags
            + str(self.fieldwidth)
            + str(self.precision)
            + str(self.lengthmodifier)
            + self.conversion)


class FormatStringSpec(InterfaceDictionaryRecord):

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        InterfaceDictionaryRecord.__init__(self, ixd, ixval)

    @property
    def argspecs(self) -> List[FormatArgSpec]:
        return [self.id.formatarg_spec(ix) for ix in self.args[1:]]

    @property
    def literal_length(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return ", ".join(str(s) for s in self.argspecs)
