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
"""Operand of an ARM assembly instruction."""

from typing import Callable, cast, Dict, List, Tuple, Type, TypeVar, TYPE_CHECKING

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.app.AppAccess import AppAccess
    from chb.app.BDictionary import BDictionary
    from chb.arm.ARMDictionary import ARMDictionary


class ARMDictionaryRecord(IndexedTableValue):

    def __init__(
            self,
            armd: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        IndexedTableValue.__init__(self, ixval.index, ixval.tags, ixval.args)
        self._armd = armd

    @property
    def armd(self) -> "ARMDictionary":
        return self._armd

    @property
    def app(self) -> "AppAccess":
        return self.armd.app

    @property
    def bd(self) -> "BDictionary":
        return self.armd.bd

    @property
    def ixd(self) -> "InterfaceDictionary":
        return self.armd.ixd

    def __str__(self) -> str:
        return "arm-record: " + str(self.key)


AdR = TypeVar("AdR", bound=ARMDictionaryRecord, covariant=True)


class ARMDictionaryRegistry:

    def __init__(self) -> None:
        self.register: Dict[Tuple[type, str], Type[ARMDictionaryRecord]] = {}

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
            ad: "ARMDictionary",
            ixval: IndexedTableValue,
            anchor: Type[AdR]) -> AdR:
        tag = ixval.tags[0]
        if (anchor, tag) not in self.register:
            raise UF.CHBError(
                "Unknown armdictionary type: " + tag + " with type " + str(anchor))
        instance = self.register[(anchor, tag)](ad, ixval)
        return cast(AdR, instance)


armregistry: ARMDictionaryRegistry = ARMDictionaryRegistry()
