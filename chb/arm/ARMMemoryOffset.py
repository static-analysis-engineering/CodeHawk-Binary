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
"""Different types of memory offset in an ARM assembly instruction operand.

Based on type arm_memory_offset_t in bchlibarm32/bCHARMTypes:

                                         tags[0]    tags    args
type arm_memory_offset_t =
  | ARMImmOffset of int                    "i"        1       1
  | ARMIndexOffset of arm_reg_t * int      "x"        2       1
  | ARMShiftedIndexOffset of               "s"        2       2
      arm_reg_t
      * register_shift_rotate_t
      * int
"""

from typing import List, TYPE_CHECKING

from chb.arm.ARMDictionaryRecord import ARMDictionaryRecord, armregistry

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMShiftRotate import ARMShiftRotate


class ARMMemoryOffset(ARMDictionaryRecord):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMDictionaryRecord.__init__(self, d, ixval)

    def __str(self) -> str:
        return "memory-offset: " + self.tags[0]


@armregistry.register_tag("i", ARMMemoryOffset)
class ARMImmOffset(ARMMemoryOffset):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMMemoryOffset.__init__(self, d, ixval)

    @property
    def immediate(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return "#" + hex(self.immediate)


@armregistry.register_tag("x", ARMMemoryOffset)
class ARMIndexOffset(ARMMemoryOffset):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMMemoryOffset.__init__(self, d, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def offset(self) -> int:
        return self.args[0]

    def __str(self) -> str:
        return self.register


@armregistry.register_tag("s", ARMMemoryOffset)
class ARMShiftedIndexOffset(ARMMemoryOffset):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMMemoryOffset.__init__(self, d, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def shift_rotate(self) -> "ARMShiftRotate":
        return self.armd.arm_register_shift(self.args[0])

    @property
    def offset(self) -> int:
        return self.args[1]

    def __str__(self) -> str:
        return self.register + "," + str(self.shift_rotate)
