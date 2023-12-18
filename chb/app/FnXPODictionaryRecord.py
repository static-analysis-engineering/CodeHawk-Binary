# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023 Aarno Labs LLC
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
"""Base class for records in function-specific XPODictionary."""

from typing import (
    Callable, cast, Dict, Generic, List, Tuple, Type, TypeVar, TYPE_CHECKING)

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.app.BDictionary import BDictionary
    from chb.app.FnXPODictionary import FnXPODictionary
    from chb.app.Function import Function
    from chb.app.FunctionInfo import FunctionInfo
    from chb.app.StringXRefs import StringsXRefs
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.invariants.FnInvDictionary import FnInvDictionary
    from chb.invariants.FnVarDictionary import FnVarDictionary
    from chb.invariants.FnVarInvDictionary import FnVarInvDictionary
    from chb.invariants.FnXprDictionary import FnXprDictionary


class FnXPODictionaryRecord(IndexedTableValue):
    """Base class for all objects kept in the FnXPODictionary."""

    def __init__(
            self,
            xpod: "FnXPODictionary",
            ixval: IndexedTableValue) -> None:
        IndexedTableValue.__init__(self, ixval.index, ixval.tags, ixval.args)
        self._xpod = xpod

    @property
    def xpod(self) -> "FnXPODictionary":
        return self._xpod

    @property
    def bcd(self) -> "BCDictionary":
        return self.xpod.bcdictionary

    @property
    def bd(self) -> "BDictionary":
        return self.xpod.bdictionary
    
    @property
    def xd(self) -> "FnXprDictionary":
        return self.xpod.xprdictionary


XpodR = TypeVar("XpodR", bound=FnXPODictionaryRecord, covariant=True)


class FnXPODictionaryRegistry:

    def __init__(self) -> None:
        self.register: Dict[Tuple[type, str], Type[FnXPODictionaryRecord]] = {}

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
            xpod: "FnXPODictionary",
            ixval: IndexedTableValue,
            superclass: Type[XpodR]) -> XpodR:
        tag = ixval.tags[0]
        if (superclass, tag) not in self.register:
            raise UF.CHBError(
                "Unknown xpodictionary type: "
                + tag
                + " with type "
                + str(superclass))
        instance = self.register[(superclass, tag)](xpod, ixval)
        return cast (XpodR, instance)


xporegistry: FnXPODictionaryRegistry = FnXPODictionaryRegistry()
        
