# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs LLC
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

from typing import Any, Dict, List, TYPE_CHECKING

from chb.jsoninterface.JSONResult import JSONResult

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.app.FunctionDictionary
    import chb.app.Instruction
    import chb.invariants.FnVarDictionary
    import chb.invariants.FnXprDictionary
    import chb.invariants.XInterval


class StackPointerOffset(IndexedTableValue):

    def __init__(
            self,
            d: "chb.app.FunctionDictionary.FunctionDictionary",
            ixval: IndexedTableValue) -> None:
        IndexedTableValue.__init__(self, ixval.index, ixval.tags, ixval.args)
        self._d = d

    @property
    def function(self) -> "chb.app.Function.Function":
        return self._d.function

    @property
    def vd(self) -> "chb.invariants.FnVarDictionary.FnVarDictionary":
        return self.function.vardictionary

    @property
    def xd(self) -> "chb.invariants.FnXprDictionary.FnXprDictionary":
        return self.function.xprdictionary

    @property
    def level(self) -> int:
        return self.args[0]

    @property
    def offset(self) -> "chb.invariants.XInterval.XInterval":
        return self.xd.interval(self.args[1])

    @property
    def is_closed(self) -> bool:
        return self.offset.is_closed

    def __str__(self) -> str:
        level = self.level + 1
        return (("[" * level)
                + " "
                + str(self.offset).rjust(4)
                + " "
                + ("]" * level))

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        if self.offset.is_singleton:
            content["value"] = self.offset.lower_bound.bound.value
        elif self.offset.is_closed:
            content["range"] = [
                self.offset.lower_bound.bound.value, self.offset.upper_bound.bound.value]
        elif self.offset.lower_bound.is_bounded:
            content["lowerbound"] = self.offset.lower_bound.bound.value
        elif self.offset.upper_bound.is_bounded:
            content["upperbound"] = self.offset.upper_bound.bound.value
        else:
            content["novalue"] = "unbounded"
        return JSONResult("stackpointeroffset", content, "ok")
