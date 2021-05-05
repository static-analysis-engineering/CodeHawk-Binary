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

from typing import cast, Callable, Dict, List, Tuple, Type, TypeVar, TYPE_CHECKING

import chb.app.DictionaryRecord as D
import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.api.InterfaceDictionary
    import chb.app.AppAccess
    import chb.app.BDictionary
    import chb.models.ModelsAccess


class InterfaceDictionaryRecord(D.DictionaryRecord):

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        D.DictionaryRecord.__init__(self, index, tags, args)
        self._d = d

    @property
    def id(self) -> "chb.api.InterfaceDictionary.InterfaceDictionary":
        return self._d

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

    def construct_instance(
            self,
            id: "chb.api.InterfaceDictionary.InterfaceDictionary",
            index: int,
            tags: List[str],
            args: List[int],
            superclass: type) -> IdR:
        if (superclass, tags[0]) not in self.register:
            raise UF.CHBError("Unknown interface dictionary type: " + tags[0])
        return cast(IdR, self.register[(superclass, tags[0])](id, index, tags, args))


apiregistry: InterfaceDictionaryRegistry = InterfaceDictionaryRegistry()
