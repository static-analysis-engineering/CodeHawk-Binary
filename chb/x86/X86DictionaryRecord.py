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
"""Basis for dictionary records in the X86 dictionary."""

from typing import Callable, cast, Dict, List, Tuple, Type, TypeVar, TYPE_CHECKING

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.api.InterfaceDictionary
    import chb.app.BDictionary
    import chb.x86.X86Access
    import chb.x86.X86Dictionary


class X86DictionaryRecord(IndexedTableValue):

    def __init__(
            self,
            x86d: "chb.x86.X86Dictionary.X86Dictionary",
            ixval: IndexedTableValue) -> None:
        IndexedTableValue.__init__(self, ixval.index, ixval.tags, ixval.args)
        self._x86d = x86d

    @property
    def x86d(self) -> "chb.x86.X86Dictionary.X86Dictionary":
        return self._x86d

    @property
    def app(self) -> "chb.x86.X86Access.X86Access":
        return self.x86d.app

    @property
    def bd(self) -> "chb.app.BDictionary.BDictionary":
        return self.x86d.bd

    @property
    def ixd(self) -> "chb.api.InterfaceDictionary.InterfaceDictionary":
        return self.x86d.ixd


X86dR = TypeVar("X86dR", bound=X86DictionaryRecord, covariant=True)


class X86DictionaryRegistry:
    def __init__(self) -> None:
        self.register: Dict[Tuple[type, str], Type[X86DictionaryRecord]] = {}

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
            x86d: "chb.x86.X86Dictionary.X86Dictionary",
            ixval: IndexedTableValue,
            anchor: Type[X86dR]) -> X86dR:
        tag = ixval.tags[0]
        if (anchor, tag) not in self.register:
            raise UF.CHBError("Unknown x86dictionary type: " + tag)
        instance = self.register[(anchor, tag)](x86d, ixval)
        return cast(X86dR, instance)


x86registry: X86DictionaryRegistry = X86DictionaryRegistry()
