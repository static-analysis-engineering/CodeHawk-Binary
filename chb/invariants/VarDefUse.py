# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022 Aarno Labs LLC
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
"""Tuple of a variable and a set of symbols representing locations."""

from typing import Sequence, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import FnVarInvDictionaryRecord
from chb.invariants.XSymbol import XSymbol
from chb.invariants.XVariable import XVariable

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.invariants.FnVarInvDictionary import FnVarInvDictionary


class VarDefUse(FnVarInvDictionaryRecord):
    """Tuple of variable and list of symbols.

    args[0]: index of variable in variable dictionary
    args[1..]: indices of symbols in variable dictionary
    """

    def __init__(
            self,
            varinvd: "FnVarInvDictionary",
            ixval: IndexedTableValue) -> None:
        FnVarInvDictionaryRecord.__init__(self, varinvd, ixval)

    @property
    def variable(self) -> XVariable:
        return self.xd.variable(self.args[0])

    @property
    def symbols(self) -> Sequence[XSymbol]:
        return [self.xd.symbol(i) for i in self.args[1:]]

    def __str__(self) -> str:
        return (
            str(self.variable)
            + ": ["
            + ", ".join(str(x) for x in self.symbols) + "]")
