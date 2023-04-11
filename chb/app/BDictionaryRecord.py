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
"""Basis for dictionary records in the basic dictionary."""

from typing import Callable, cast, Dict, List, Tuple, Type, TypeVar, TYPE_CHECKING

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    import chb.app.BDictionary


class BDictionaryRecord(IT.IndexedTableValue):
    """Base class for all objects kept in the BDictionary."""

    def __init__(
            self,
            bd: "chb.app.BDictionary.BDictionary",
            ixval: IT.IndexedTableValue) -> None:
        IT.IndexedTableValue.__init__(self, ixval.index, ixval.tags, ixval.args)
        self._bd = bd

    @property
    def bd(self) -> "chb.app.BDictionary.BDictionary":
        return self._bd


BdR = TypeVar("BdR", bound=BDictionaryRecord, covariant=True)


class BDictionaryRegistry:

    def __init__(self) -> None:
        self.register: Dict[Tuple[type, str], Type[BDictionaryRecord]] = {}

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
            bd: "chb.app.BDictionary.BDictionary",
            ixval: IT.IndexedTableValue,
            anchor: Type[BdR]) -> BdR:
        tag = ixval.tags[0]
        if (anchor, tag) not in self.register:
            raise UF.CHBError("Unknown bdictionary type: " + tag)
        instance = self.register[(anchor, tag)](bd, ixval)
        return cast(BdR, instance)


bdregistry: BDictionaryRegistry = BDictionaryRegistry()
