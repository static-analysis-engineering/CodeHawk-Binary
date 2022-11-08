# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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
"""Base class for records in function-specific variable directory."""

from typing import (
    Callable, cast, Dict, Generic, List, Tuple, Type, TypeVar, TYPE_CHECKING)

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.InterfaceDictionary import InterfaceDictionary
    import chb.app.AppAccess
    from chb.app.BDictionary import BDictionary
    from chb.app.Function import Function
    from chb.app.FunctionInfo import FunctionInfo
    from chb.app.StringXRefs import StringsXRefs
    from chb.invariants.FnInvDictionary import FnInvDictionary
    from chb.invariants.FnVarDictionary import FnVarDictionary
    from chb.invariants.FnVarInvDictionary import FnVarInvDictionary
    from chb.invariants.FnXprDictionary import FnXprDictionary


class FnXprDictionaryRecord(IndexedTableValue):
    """Base class for all objects kept in the FnXprDictionary."""

    def __init__(
            self,
            xd: "FnXprDictionary",
            ixval: IndexedTableValue) -> None:
        IndexedTableValue.__init__(self, ixval.index, ixval.tags, ixval.args)
        self._xd = xd

    @property
    def xd(self) -> "FnXprDictionary":
        return self._xd

    @property
    def vd(self) -> "FnVarDictionary":
        return self._xd.vd

    @property
    def function(self) -> "Function":
        return self.vd.function

    @property
    def bd(self) -> "BDictionary":
        return self.vd.bd

    @property
    def app(self) -> "chb.app.AppAccess.AppAccess":
        return self.bd.app

    @property
    def finfo(self) -> "FunctionInfo":
        return self.xd.finfo


class FnVarDictionaryRecord(IndexedTableValue):
    """Base class for all objects kept in the FnVarDictionary."""

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        IndexedTableValue.__init__(self, ixval.index, ixval.tags, ixval.args)
        self._vd = vd

    @property
    def vd(self) -> "chb.invariants.FnVarDictionary.FnVarDictionary":
        return self._vd

    @property
    def function(self) -> "Function":
        return self.vd.function

    @property
    def xd(self) -> "FnXprDictionary":
        return self.vd.xd

    @property
    def bd(self) -> "BDictionary":
        return self.vd.bd

    @property
    def ixd(self) -> "InterfaceDictionary":
        return self.vd.ixd

    @property
    def faddr(self) -> str:
        return self.vd.faddr

    @property
    def finfo(self) -> "FunctionInfo":
        return self.xd.finfo

    @property
    def stringsxrefs(self) -> "StringsXRefs":
        return self.vd.stringsxrefs


class FnInvDictionaryRecord(IndexedTableValue):
    """Base class for all objects kept in the FnInvDictionary."""

    def __init__(
            self,
            invd: "FnInvDictionary",
            ixval: IndexedTableValue) -> None:
        IndexedTableValue.__init__(self, ixval.index, ixval.tags, ixval.args)
        self._invd = invd

    @property
    def invd(self) -> "FnInvDictionary":
        return self._invd

    @property
    def vd(self) -> "FnVarDictionary":
        return self.invd.vd

    @property
    def xd(self) -> "FnXprDictionary":
        return self.invd.xd

    @property
    def function(self) -> "Function":
        return self.invd.function


class FnVarInvDictionaryRecord(IndexedTableValue):
    """Base class for objects kept in the FnVarInvDictionary."""

    def __init__(
            self,
            varinvd: "FnVarInvDictionary",
            ixval: IndexedTableValue) -> None:
        IndexedTableValue.__init__(self, ixval.index, ixval.tags, ixval.args)
        self._varinvd = varinvd

    @property
    def varinvd(self) -> "FnVarInvDictionary":
        return self._varinvd

    @property
    def vd(self) -> "FnVarDictionary":
        return self.varinvd.vd

    @property
    def xd(self) -> "FnXprDictionary":
        return self.varinvd.xd

    @property
    def function(self) -> "Function":
        return self.varinvd.function


VdR = TypeVar("VdR", bound=FnVarDictionaryRecord, covariant=True)


class VarDictionaryRegistry:

    def __init__(self) -> None:
        self.register: Dict[Tuple[type, str], Type[FnVarDictionaryRecord]] = {}

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
            vd: "FnVarDictionary",
            ixval: IndexedTableValue,
            superclass: type) -> VdR:
        tag = ixval.tags[0]
        if (superclass, tag) not in self.register:
            raise UF.CHBError(
                "Unknown vardictionary type: "
                + tag
                + " with type "
                + str(superclass))
        instance = self.register[(superclass, tag)](vd, ixval)
        return cast(VdR, instance)


varregistry: VarDictionaryRegistry = VarDictionaryRegistry()


XdR = TypeVar("XdR", bound=FnXprDictionaryRecord, covariant=True)


class XprDictionaryRegistry:

    def __init__(self) -> None:
        self.register: Dict[Tuple[type, str], Type[FnXprDictionaryRecord]] = {}

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
            xd: "chb.invariants.FnXprDictionary.FnXprDictionary",
            ixval: IndexedTableValue,
            superclass: type) -> XdR:
        tag = ixval.tags[0]
        if (superclass, tag) not in self.register:
            raise UF.CHBError("Unknown xprdictionary type: " + tag)
        instance = self.register[(superclass, tag)](xd, ixval)
        return cast(XdR, instance)


xprregistry: XprDictionaryRegistry = XprDictionaryRegistry()


IdR = TypeVar("IdR", bound=FnInvDictionaryRecord, covariant=True)


class InvDictionaryRegistry:

    def __init__(self) -> None:
        self.register: Dict[Tuple[type, str], Type[FnInvDictionaryRecord]] = {}

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
            invd: "chb.invariants.FnInvDictionary.FnInvDictionary",
            ixval: IndexedTableValue,
            superclass: type) -> IdR:
        tag = ixval.tags[0]
        if (superclass, tag) not in self.register:
            raise UF.CHBError("Unknown invdictionary type: " + tag)
        instance = self.register[(superclass, tag)](invd, ixval)
        return cast(IdR, instance)


invregistry: InvDictionaryRegistry = InvDictionaryRegistry()


VIdR = TypeVar("VIdR", bound=FnVarInvDictionaryRecord, covariant=True)


class VarInvDictionaryRegistry:

    def __init__(self) -> None:
        self.register: Dict[Tuple[type, str], Type[FnVarInvDictionaryRecord]] = {}

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
            varinvd: "chb.invariants.FnVarInvDictionary.FnVarInvDictionary",
            ixval: IndexedTableValue,
            superclass: type) -> VIdR:
        tag = ixval.tags[0]
        if (superclass, tag) not in self.register:
            raise UF.CHBError("Unknown varinvdictionary type: " + tag)
        instance = self.register[(superclass, tag)](varinvd, ixval)
        return cast(VIdR, instance)


varinvregistry: VarInvDictionaryRegistry = VarInvDictionaryRegistry()
