# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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
"""Operand of an Power assembly instruction."""

from typing import Callable, cast, Dict, List, Tuple, Type, TypeVar, TYPE_CHECKING

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.InterfaceDictionary import InterfaceDictionary
    from chb.app.AppAccess import AppAccess
    from chb.app.BDictionary import BDictionary
    from chb.pwr.PowerDictionary import PowerDictionary


class PowerDictionaryRecord(IndexedTableValue):

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue
    ) -> None:
        self._pwrd = pwrd

    @property
    def pwrd(self) -> "PowerDictionary":
        return self._pwrd

    @property
    def app(self) -> "AppAccess":
        return self.pwrd.app

    @property
    def bd(self) -> "BDictionary":
        return self.pwrd.bd

    @property
    def ixd(self) -> "InterfaceDictionary":
        return self.pwrd.ixd

    def __str__(self) -> str:
        return "pwr-record: " + str(self.key)


PdR = TypeVar("PdR", bound=PowerDictionaryRecord, covariant=True)


class PowerDictionaryRegistry:

    def __init__(self) -> None:
        self.register: Dict[Tuple[type, str], Type[PowerDictionaryRecord]] = {}

    def register_tag(self, tag: str, anchor: type) -> Callable[[type], type]:

        def handler(t: type) -> type:
            self.register[(anchor, tag)] = t
            return t

        return handler

    def mk_instance(
            self,
            pwrd: "PowerDictionary",
            ixval: IndexedTableValue,
            anchor: Type[PdR]) -> PdR:
        tag = ixval.tags[0]
        if (anchor, tag) not in self.register:
            raise UF.CHBError(
                "Unknown pwrdictionary type: "
                + tag
                + " with type "
                + str(anchor))
        instance = self.register[(anchor, tag)](pwrd, ixval)
        return cast(PdR, instance)


pwrregistry: PowerDictionaryRegistry = PowerDictionaryRegistry()
