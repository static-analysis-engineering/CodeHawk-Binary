# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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
"""Symbolic value, identified by name and sequence number"""

from typing import List, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import FnXprDictionaryRecord

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.invariants.FnXprDictionary import FnXprDictionary


class XSymbol(FnXprDictionaryRecord):
    """Symbolic value.

    tags[1..]: attributes
    args[0]: sequence number
    """

    def __init__(
            self,
            xd: "FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        FnXprDictionaryRecord.__init__(self, xd, ixval)

    @property
    def name(self) -> str:
        seqnr = self.seqnr
        if self.finfo.has_variable_name(seqnr):
            return self.finfo.variable_name(seqnr)
        else:
            return '?' if self.tags[0] == 'tmpN' else self.tags[0]

    @property
    def attrs(self) -> List[str]:
        return self.tags[1:]

    @property
    def seqnr(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        seqnr = self.seqnr
        if len(self.tags) > 1:
            attrs = "_" + "_".join(self.attrs)
        else:
            attrs = ""
        pseqnr = "_s:" + str(seqnr) if seqnr >= 0 else ""
        return self.name + attrs + pseqnr
