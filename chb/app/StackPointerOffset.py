# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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
"""Stack pointer offset from position at start of function."""

import chb.app.DictionaryRecord as D

from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    import chb.app.FunctionDictionary
    import chb.invariants.BXpr


class StackPointerOffset(D.DictionaryRecord):

    def __init__(
            self,
            d: "chb.app.FunctionDictionary.FunctionDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        D.DictionaryRecord.__init__(self, index, tags, args)
        self.fnd = d
        self._fn = d.function
        self._vd = self._fn.vardictionary
        self._xd = self._fn.xprdictionary

    @property
    def level(self) -> int:
        return self.args[0]

    @property
    def offset(self) -> "chb.invariants.BXpr.BXInterval":
        return self._xd.get_interval(self.args[1])

    @property
    def is_closed(self) -> bool:
        return self.offset.is_closed()

    def __str__(self):
        level = self.level + 1
        return (("[" * level)
                + " "
                + str(self.offset).rjust(4)
                + " "
                + ("]" * level))
