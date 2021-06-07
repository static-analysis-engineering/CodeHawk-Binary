# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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
"""Memory offset representation.

Represents memory_offset_t in bchlib/bCHLibTypes:
                                                       tags[0]  tags   args
type memory_offset_t =
  | NoOffset                                             "n"      1      0
  | ConstantOffset of numerical_t * memory_offset_t      "c"      2      1
  | IndexOffset of variable_t * int * memory_offset_t    "i"      1      3
  | UnknownOffset                                        "u"      1      0

"""

from typing import List, TYPE_CHECKING

from chb.invariants.FnDictionaryRecord import FnVarDictionaryRecord, varregistry

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.invariants.FnVarDictionary
    from chb.invariants.XVariable import XVariable


class VMemoryOffset(FnVarDictionaryRecord):

    def __init__(
            self,
            vd: "chb.invariants.FnVarDictionary.FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        FnVarDictionaryRecord.__init__(self, vd, ixval)

    @property
    def is_constant_offset(self) -> bool:
        return False

    @property
    def is_constant_value_offset(self) -> bool:
        return False

    @property
    def is_index_offset(self) -> bool:
        return False

    @property
    def is_no_offset(self) -> bool:
        return False

    @property
    def is_unknown_offset(self) -> bool:
        return False

    def has_no_offset(self) -> bool:
        return False

    def offsetvalue(self) -> int:
        raise UF.CHBError("Offsetvalue is not supported for " + str(self))

    def __str__(self) -> str:
        return "memory-offset:" + self.tags[0]


@varregistry.register_tag("n", VMemoryOffset)
class VMemoryOffsetNoOffset(VMemoryOffset):
    """No offset. """

    def __init__(
            self,
            vd: "chb.invariants.FnVarDictionary.FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryOffset.__init__(self, vd, ixval)

    def offsetvalue(self) -> int:
        return 0

    @property
    def is_no_offset(self) -> bool:
        return True

    def __str__(self) -> str:
        return ""


@varregistry.register_tag("c", VMemoryOffset)
class VMemoryOffsetConstantOffset(VMemoryOffset):
    """Constant offset.

    tags[1]: constant offset (string)
    args[0]: index of next-level offset in vardictionary
    """

    def __init__(
            self,
            vd: "chb.invariants.FnVarDictionary.FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryOffset.__init__(self, vd, ixval)

    def offsetvalue(self) -> int:
        if self.is_constant_value_offset:
            return int(self.tags[1]) + self.offset.offsetvalue()
        else:
            raise UF.CHBError("Has additional offset: " + str(self.offset))

    @property
    def offset(self) -> VMemoryOffset:
        return self.vd.memory_offset(self.args[0])

    @property
    def is_constant_offset(self) -> bool:
        return True

    @property
    def is_constant_value_offset(self) -> bool:
        return self.has_no_offset() or self.offset.has_no_offset()

    def has_no_offset(self) -> bool:
        return self.offset.is_no_offset

    def __str__(self) -> str:
        if self.has_no_offset():
            return str(self.offsetvalue())
        else:
            return str(self.offsetvalue()) + "." + str(self.offset)


@varregistry.register_tag("i", VMemoryOffset)
class VMemoryOffsetIndexOffset(VMemoryOffset):
    """Index offset.

    args[0]: index of indexvariable in xprdictionary
    args[1]: size of element
    args[2]: index of next-level offset in vardictionary
    """

    def __init__(
            self,
            vd: "chb.invariants.FnVarDictionary.FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryOffset.__init__(self, vd, ixval)

    @property
    def indexvariable(self) -> "XVariable":
        return self.xd.variable(self.args[0])

    @property
    def elementsize(self) -> int:
        return self.args[1]

    @property
    def offset(self) -> VMemoryOffset:
        return self.vd.memory_offset(self.args[2])

    @property
    def is_index_offset(self) -> bool:
        return True

    def __str__(self) -> str:
        return "[" + str(self.indexvariable) + "]" + str(self.offset)


@varregistry.register_tag("u", VMemoryOffset)
class VMemoryOffsetUnknown(VMemoryOffset):

    def __init__(
            self,
            vd: "chb.invariants.FnVarDictionary.FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VMemoryOffset.__init__(self, vd, ixval)

    @property
    def is_unknown_offset(self) -> bool:
        return True

    def __str__(self) -> str:
        return "?"
