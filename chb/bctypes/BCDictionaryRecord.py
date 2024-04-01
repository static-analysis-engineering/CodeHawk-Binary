# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
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
"""Dictionary record of CIL-types as produced by the CIL parser."""

from typing import (
    Any, Callable, cast, Dict, List, Tuple, Type, TypeVar, TYPE_CHECKING)

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCVisitor import BCVisitor


class BCDictionaryRecord(IndexedTableValue):

    def __init__(
            self,
            bcd: "BCDictionary",
            ixval: IndexedTableValue) -> None:
        IndexedTableValue.__init__(self, ixval.index, ixval.tags, ixval.args)
        self._bcd = bcd
        self._ixval = ixval

    @property
    def bcd(self) -> "BCDictionary":
        return self._bcd

    @property
    def ixval(self) -> IndexedTableValue:
        return self._ixval

    def accept(self, visitor: "BCVisitor") -> None:
        pass


BCdR = TypeVar("BCdR", bound=BCDictionaryRecord, covariant=True)


class BCDictionaryRegistry:

    def __init__(self) -> None:
        self.register: Dict[Tuple[type, str], Type[BCDictionaryRecord]] = {}

    def register_tag(
            self,
            tag: str,
            anchor: type) -> Callable[[type], type]:
        def handler(t: type) -> type:
            self.register[(anchor, tag)] = t
            return t
        return handler

    def mk_instance(
            self,
            bcd: "BCDictionary",
            ixval: IndexedTableValue,
            anchor: Type[BCdR]) -> BCdR:
        tag = ixval.tags[0]
        if (anchor, tag) not in self.register:
            raise UF.CHBError(
                "Unknown cil dictionary type: "
                + tag
                + " with type "
                + str(anchor))
        instance = self.register[(anchor, tag)](bcd, ixval)
        return cast(BCdR, instance)


bcregistry: BCDictionaryRegistry = BCDictionaryRegistry()
