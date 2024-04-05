# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021-2024 Aarno Labs LLC
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
"""Integer interval, possibly unbounded"""

from typing import List, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import FnXprDictionaryRecord
from chb.invariants.XBound import XBound

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.invariants.FnXprDictionary import FnXprDictionary


class XInterval(FnXprDictionaryRecord):

    def __init__(
            self,
            xd: "FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        FnXprDictionaryRecord.__init__(self, xd, ixval)

    @property
    def lower_bound(self) -> XBound:
        return self.xd.bound(self.args[0])

    @property
    def upper_bound(self) -> XBound:
        return self.xd.bound(self.args[1])

    @property
    def is_lower_bounded(self) -> bool:
        return self.lower_bound.is_bounded

    @property
    def is_upper_bounded(self) -> bool:
        return self.upper_bound.is_bounded

    @property
    def is_closed(self) -> bool:
        return self.lower_bound.is_bounded and self.upper_bound.is_bounded

    @property
    def is_singleton(self) -> bool:
        return (
            self.is_closed
            and str(self.lower_bound.bound) == str(self.upper_bound.bound))

    def lowerbound(self) -> int:
        if self.is_lower_bounded:
            return self.lower_bound.bound.value
        else:
            raise UF.CHBError(
                "interval does not have a lower bound: " + str(self))

    def upperbound(self) -> int:
        if self.is_upper_bounded:
            return self.upper_bound.bound.value
        else:
            raise UF.CHBError(
                "interval does not have an upper bound: " + str(self))

    def value(self) -> int:
        if self.is_singleton:
            return self.lower_bound.bound.value
        else:
            raise UF.CHBError(
                "interval is not a singleton value: " + str(self))

    def __str__(self) -> str:
        if self.is_singleton:
            return str(self.value())
        elif self.is_closed:
            return (
                str(self.lowerbound())
                + ';'
                + str(self.upperbound()))
        elif self.is_lower_bounded:
            return str(self.lowerbound()) + '; oo'
        elif self.is_upper_bounded:
            return 'oo + ;' + str(self.upperbound())
        else:
            return 'oo ; oo'
