# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021-2023 Aarno Labs LLC
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
"""Bound on integer range."""

from typing import List, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import FnXprDictionaryRecord, xprregistry
from chb.invariants.XNumerical import XNumerical

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue


if TYPE_CHECKING:
    from chb.invariants.FnXprDictionary import FnXprDictionary


class XBound(FnXprDictionaryRecord):

    def __init__(
            self,
            xd: "FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        FnXprDictionaryRecord.__init__(self, xd, ixval)

    @property
    def is_min_inf(self) -> bool:
        return False

    @property
    def is_max_inf(self) -> bool:
        return False

    @property
    def is_bounded(self) -> bool:
        return False

    @property
    def bound(self) -> XNumerical:
        raise UF.CHBError("bound not defined on " + str(self))


@xprregistry.register_tag("m", XBound)
class XMinusInfBound(XBound):
    """Minus infinity bound."""

    def __init__(
            self,
            xd: "FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        XBound.__init__(self, xd, ixval)

    @property
    def is_min_inf(self) -> bool:
        return True

    def __str__(self) -> str:
        return "minus infinity"


@xprregistry.register_tag("p", XBound)
class XPlusInfBound(XBound):
    """Plus infinity bound."""

    def __init__(
            self,
            xd: "FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        XBound.__init__(self, xd, ixval)

    @property
    def is_max_inf(self) -> bool:
        return True

    def __str__(self) -> str:
        return "plus infinity"


@xprregistry.register_tag("n", XBound)
class XNumberBound(XBound):
    """Numerical bound.

    args[0]: index of numerical in xd
    """

    def __init__(
            self,
            xd: "FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        XBound.__init__(self, xd, ixval)

    @property
    def is_bounded(self) -> bool:
        return True

    @property
    def bound(self) -> XNumerical:
        return self.xd.numerical(self.args[0])

    def __str__(self) -> str:
        return str(self.bound)
