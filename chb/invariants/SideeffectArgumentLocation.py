# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2025  Aarno Labs LLC
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
"""

Based on sideeffect_argument_location in bCHLibTypes:

type sideeffect_argument_location_t =
| SEGlobal of doubleword_int    (* address of global variable passed *)
| SEStack of numerical_int      (* stack offset (negative for local stack) passed *)
| SEDescr of string             (* unidentified address *)
"""

from typing import TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import FnVarDictionaryRecord, varregistry

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.bctypes.BCTyp import BCTyp
    from chb.invariants.FnVarDictionary import FnVarDictionary


class SideeffectArgumentLocation(FnVarDictionaryRecord):

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        FnVarDictionaryRecord.__init__(self, vd, ixval)

    @property
    def is_global_location(self) -> bool:
        return False

    @property
    def is_stack_location(self) -> bool:
        return False

    @property
    def is_unknown_location(self) -> bool:
        return False

    def __str__(self) -> str:
        return "sideeffect-argument-location:" + self.tags[0]


@varregistry.register_tag("g", SideeffectArgumentLocation)
class SideeffectArgumentGlobalLocation(SideeffectArgumentLocation):

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        SideeffectArgumentLocation.__init__(self, vd, ixval)

    @property
    def is_global_location(self) -> bool:
        return True

    @property
    def gaddr(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return "seglobal:" + self.gaddr


@varregistry.register_tag("s", SideeffectArgumentLocation)
class SideeffectArgumentStackLocation(SideeffectArgumentLocation):

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        SideeffectArgumentLocation.__init__(self, vd, ixval)

    @property
    def is_stack_location(self) -> bool:
        return True

    @property
    def offset(self) -> int:
        return int(self.tags[1])

    def __str__(self) -> str:
        return "sestack:" + str(self.offset)


@varregistry.register_tag("d", SideeffectArgumentLocation)
class SideeffectArgumentUnknownLocation(SideeffectArgumentLocation):

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        SideeffectArgumentLocation.__init__(self, vd, ixval)

    @property
    def is_unknown_location(self) -> bool:
        return True

    @property
    def description(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return "sedescr:" + str(self.description)
