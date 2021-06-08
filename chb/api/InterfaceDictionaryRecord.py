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
"""Basis for dictionary records in the interface dictionary."""

from typing import cast, Callable, Dict, List, Tuple, Type, TypeVar, TYPE_CHECKING

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    import chb.api.InterfaceDictionary
    import chb.app.AppAccess
    import chb.app.BDictionary
    import chb.models.ModelsAccess


class InterfaceDictionaryRecord(IT.IndexedTableValue):

    def __init__(
            self,
            id: "chb.api.InterfaceDictionary.InterfaceDictionary",
            ixval: IT.IndexedTableValue) -> None:
        IT.IndexedTableValue.__init__(self, ixval.index, ixval.tags, ixval.args)
        self._id = id

    @property
    def id(self) -> "chb.api.InterfaceDictionary.InterfaceDictionary":
        return self._id

    @property
    def bd(self) -> "chb.app.BDictionary.BDictionary":
        return self.id.bdictionary

    @property
    def app(self) -> "chb.app.AppAccess.AppAccess":
        return self.id.app

    @property
    def models(self) -> "chb.models.ModelsAccess.ModelsAccess":
        return self.app.models


IdR = TypeVar("IdR", bound=InterfaceDictionaryRecord, covariant=True)


class InterfaceDictionaryRegistry:

    def __init__(self) -> None:
        self.register: Dict[Tuple[type, str], Type[InterfaceDictionaryRecord]] = {}

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
            id: "chb.api.InterfaceDictionary.InterfaceDictionary",
            ixval: IT.IndexedTableValue,
            superclass: type) -> IdR:
        tag = ixval.tags[0]
        if (superclass, tag) not in self.register:
            raise UF.CHBError("Unknown interface dictionary type: " + tag)
        instance = self.register[(superclass, tag)](id, ixval)
        return cast(IdR, instance)


apiregistry: InterfaceDictionaryRegistry = InterfaceDictionaryRegistry()
