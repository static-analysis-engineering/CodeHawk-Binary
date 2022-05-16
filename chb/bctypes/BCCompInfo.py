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

from typing import Any, cast, Dict, List, Optional, Tuple, TYPE_CHECKING

from chb.bctypes.BCDictionaryRecord import BCDictionaryRecord

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCFieldInfo import BCFieldInfo
    from chb.bctypes.BCTyp import BCTyp


class OffsetAccumulator:

    def __init__(
            self, first_free: int, last_start: int, last_width: int) -> None:
        self._first_free = first_free
        self._last_start = last_start
        self._last_width = last_width

    @property
    def first_free(self) -> int:
        return self._first_free

    @property
    def last_start(self) -> int:
        return self._last_start

    @property
    def last_width(self) -> int:
        return self._last_width

    def __str__(self) -> str:
        return (
            "("
            + str(self.first_free)
            + ", "
            + str(self.last_start)
            + ", "
            + str(self.last_width))


class BCCompInfo(BCDictionaryRecord):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IT.IndexedTableValue) -> None:
        BCDictionaryRecord.__init__(self, bcd, ixval)

    @property
    def cname(self) -> str:
        return self.tags[0]

    @property
    def ckey(self) -> int:
        return self.args[0]

    @property
    def is_struct(self) -> bool:
        return self.args[1] == 1

    @property
    def is_union(self) -> bool:
        return self.args[1] == 0

    @property
    def fieldinfos(self) -> List["BCFieldInfo"]:
        return [self.bcd.fieldinfo(i) for i in self.args[3:]]

    def is_leq(self, other: "BCCompInfo") -> bool:

        def foffset_leq(
                foffset1: Tuple[int, "BCFieldInfo"],
                foffset2: Tuple[int, "BCFieldInfo"]) -> bool:
            if foffset1[0] == foffset2[0]:
                return foffset1[1].is_leq(foffset2[1])
            else:
                return False

        return all(foffset_leq(foffset1, foffset2)
                   for (foffset1, foffset2)
                   in zip(self.fieldoffsets(), other.fieldoffsets()))

    def byte_size(self) -> int:
        """Return size in bytes."""

        if len(self.fieldinfos) == 0:
            return 4

        def addt(size: int, roundto: int) -> int:
            return ((((size + roundto) - 1) // roundto) * roundto)

        def aux(finfo: "BCFieldInfo", acc: OffsetAccumulator) -> OffsetAccumulator:
            fsize = finfo.byte_size()
            news = addt(acc.first_free, finfo.alignment())
            newf = news + fsize
            return OffsetAccumulator(newf, news, fsize)

        acc = OffsetAccumulator(0, 0, 0)
        for finfo in self.fieldinfos:
            acc = aux(finfo, acc)

        return addt(acc.first_free, self.alignment())

    def alignment(self) -> int:
        """Return size of largest field."""

        if len(self.fieldinfos) == 0:
            return 0
        else:
            return max(finfo.alignment() for finfo in self.fieldinfos)

    def fieldoffsets(self) -> List[Tuple[int, "BCFieldInfo"]]:
        """Return a list of pairs with offset in bytes and fieldinfo."""

        def addt(size: int, roundto: int) -> int:
            return ((((size + roundto) - 1) // roundto) * roundto)

        def aux(finfo: "BCFieldInfo", acc: OffsetAccumulator) -> OffsetAccumulator:
            fsize = finfo.byte_size()
            news = addt(acc.first_free, finfo.alignment())
            newf = news + fsize
            return OffsetAccumulator(newf, news, fsize)

        result: List[Tuple[int, "BCFieldInfo"]] = []
        acc = OffsetAccumulator(0, 0, 0)
        for finfo in self.fieldinfos:
            acc = aux(finfo, acc)
            result.append((acc.last_start, finfo))

        return result

    def has_field_at_offset(self, offset: int) -> bool:
        for (i, finfo) in sorted(self.fieldoffsets()):
            if i == offset:
                return True
        else:
            return False

    def field_at_offset(self, offset: int) -> Tuple["BCFieldInfo", int]:
        """Return the field at the max offset less than or equal to offset.

        If the field is not at offset, also return the remaining offset."""

        if offset < 0:
            raise UF.CHBError(
                "Negative offset in field_at_offset: " + str(offset))

        prev: Optional[Tuple[int, "BCFieldInfo"]] = None
        for (i, finfo) in sorted(self.fieldoffsets()):
            if i == offset:
                return (finfo, 0)
            elif i > offset:
                prev = cast(Tuple[int, "BCFieldInfo"], prev)
                return (prev[1], offset - prev[0])
            else:
                prev = (i, finfo)
        else:
            if (offset - i) < finfo.byte_size():
                return (finfo, offset - i)

            else:
                raise UF.CHBError(
                    "No field found at offset "
                    + str(offset)
                    + " in struct "
                    + self.cname
                    + " (Offsets found: "
                    + ", ".join(str(f[0]) + ":" + f[1].fieldname
                                for f in self.fieldoffsets())
                    + ")"
                    + " (Alignment: "
                    + str(self.alignment())
                    + ")")

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("struct " + self.cname + "{")
        for (offset, f) in self.fieldoffsets():
            lines.append("  " + str(f) + " // offset: " + str(offset))
        lines.append("}")
        return "\n".join(lines)
