# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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
"""Invariant expressed by a linear equality."""

from typing import Any, Dict, Iterator, List, Sequence, Tuple, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import FnInvDictionaryRecord
from chb.invariants.XSymbol import XSymbol
from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.invariants.FnInvDictionary import FnInvDictionary


class LinearEquality(FnInvDictionaryRecord):
    """Linear equality expressed as a1.f1 + ... + an.fn = c .

    tags[0]: constant c (as string)
    tags[1..]: coefficients a1 ... an (as string)
    args[0..]: indices of factor variables f1 ... fn in xprdictionary
    """

    def __init__(
            self,
            invd: "FnInvDictionary",
            ixval: IndexedTableValue) -> None:
        FnInvDictionaryRecord.__init__(self, invd, ixval)

    @property
    def constant(self) -> int:
        return int(self.tags[0])

    @property
    def coefficients(self) -> Sequence[int]:
        return [int(x) for x in self.tags[1:]]

    @property
    def factors(self) -> Sequence[XVariable]:
        return [self.xd.variable(i) for i in self.args]

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["constant"] = self.constant
        content["coeffs"] = self.coefficients
        content["factors"] = jfactors = []
        for factor in self.factors:
            fresult = factor.to_json_result()
            if not fresult.is_ok:
                reason = (
                    "linear equality: failure for factor "
                    + str(factor)
                    + ": "
                    + str(fresult.reason))
                return JSONResult("linearequality", {}, "fail", reason)
            else:
                jfactors.append(fresult.content)
        content["txtrep"] = str(self)
        return JSONResult("linearequality", content, "ok")

    def __str__(self) -> str:
        cfs: Iterator[Tuple[int, XVariable]] = zip(self.coefficients, self.factors)

        def term(c: int, f: XVariable) -> str:
            if c == 1:
                return str(f)
            elif c == -1:
                return '-' + str(f)
            else:
                return str(c) + '.' + str(f)

        terms = " + ".join([term(c, f) for (c, f) in cfs])
        return terms + " = " + str(self.constant)
