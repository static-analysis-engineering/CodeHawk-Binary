# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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
"""Base of a memory reference.

Based on memory_base_t in bCHLibTypes:

type memory_base_t =
| BLocalStackFrame   (* local stack frame *)   "l"
| BRealignedStackFrame  (* local stack frame after realignment *)  "r"
| BAllocatedStackFrame  (* extended stack frame from alloca *)     "a"
| BGlobal   (* global data *)                                      "g"
| BaseVar of variable_t (* base provided by an externally controlled variable *) "v"
| BaseUnknown of string (* address without interpretation *)  "u"

"""

from typing import List, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import FnVarDictionaryRecord, varregistry

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.invariants.FnVarDictionary
    from chb.invariants.XVariable import XVariable


class VMemoryBase(FnVarDictionaryRecord):

    def __init__(
            self,
            vd: "chb.invariants.FnVarDictionary.FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        FnVarDictionaryRecord.__init__(self, vd, ixval)

    @property
    def is_local_stack_frame(self) -> bool:
        return False

    @property
    def is_allocated_stack_frame(self) -> bool:
        return False

    @property
    def is_realigned_stack_frame(self) -> bool:
        return False

    @property
    def is_basevar(self) -> bool:
        return False

    @property
    def is_global(self) -> bool:
        return False

    @property
    def is_unknown(self) -> bool:
        return False

    @property
    def basevar(self) -> "XVariable":
        raise UF.CHBError("Basevar not supported for " + str(self))

    def __str__(self) -> str:
        return "memorybase:" + self.tags[0]


@varregistry.register_tag("l", VMemoryBase)
class VMemoryBaseLocalStackFrame(VMemoryBase):

    def __init__(
            self,
            vd: "chb.invariants.FnVarDictionary.FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryBase.__init__(self, vd, ixval)

    @property
    def is_local_stack_frame(self) -> bool:
        return True

    def __str__(self) -> str:
        return "stack:"


@varregistry.register_tag("a", VMemoryBase)
class VMemoryBaseAllocatedStackFrame(VMemoryBase):

    def __init__(
            self,
            vd: "chb.invariants.FnVarDictionary.FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryBase.__init__(self, vd, ixval)

    @property
    def is_allocated_stack_frame(self) -> bool:
        return True

    def __str__(self) -> str:
        return "allocated-stack:"


@varregistry.register_tag("r", VMemoryBase)
class VMemoryBaseRealignedStackFrame(VMemoryBase):

    def __init__(
            self,
            vd: "chb.invariants.FnVarDictionary.FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryBase.__init__(self, vd, ixval)

    @property
    def is_realigned_stack_frame(self) -> bool:
        return True

    def __str__(self) -> str:
        return "realigned-stack:"


@varregistry.register_tag("v", VMemoryBase)
class VMemoryBaseBaseVar(VMemoryBase):
    """Base variable that is a constant symbol.

    args[0]: index of variable in xprdictionary
    """

    def __init__(
            self,
            vd: "chb.invariants.FnVarDictionary.FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryBase.__init__(self, vd, ixval)

    @property
    def is_basevar(self) -> bool:
        return True

    @property
    def basevar(self) -> "XVariable":
        return self.xd.variable(self.args[0])

    def __str__(self) -> str:
        return str(self.basevar)


@varregistry.register_tag("g", VMemoryBase)
class VMemoryBaseGlobal(VMemoryBase):

    def __init__(
            self,
            vd: "chb.invariants.FnVarDictionary.FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryBase.__init__(self, vd, ixval)

    @property
    def is_global(self) -> bool:
        return True

    def __str__(self) -> str:
        return "base:global"


@varregistry.register_tag("u", VMemoryBase)
class VMemoryBaseUnknown(VMemoryBase):
    """Base variable of unknown location.

    args[0]: index of description in bd
    """

    def __init__(
            self,
            vd: "chb.invariants.FnVarDictionary.FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryBase.__init__(self, vd, ixval)

    @property
    def desc(self) -> str:
        return self.bd.string(self.args[0])

    @property
    def is_unknown(self) -> bool:
        return True

    def __str__(self) -> str:
        return "unknownbase(" + self.desc + "):"
