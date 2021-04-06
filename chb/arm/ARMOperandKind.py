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

from typing import List, TYPE_CHECKING

import chb.arm.ARMDictionaryRecord as D
import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.app.BDictionary
    import chb.arm.ARMDictionary
    import chb.arm.ARMMemoryOffset
    import chb.arm.ARMShiftRotate


class ARMOperandKind(D.ARMDictionaryRecord):

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        D.ARMDictionaryRecord.__init__(self, d, index, tags, args)

    def is_arm_absolute(self) -> bool:
        return False

    def is_arm_immediate(self) -> bool:
        return False


class ARMRegisterOp(ARMOperandKind):

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        ARMOperandKind.__init__(self, d, index, tags, args)

    def get_register(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return self.get_register()


class ARMRegListOp(ARMOperandKind):

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        ARMOperandKind.__init__(self, d, index, tags, args)

    def get_registers(self) -> List[str]:
        return self.tags[1:]

    def __str__(self) -> str:
        return "{" + ",".join(self.get_registers()) + "}"


class ARMShiftedRegisterOp(ARMOperandKind):

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        ARMOperandKind.__init__(self, d, index, tags, args)

    def get_register(self) -> str:
        return self.tags[1]

    def get_srt(self) -> "chb.arm.ARMShiftRotate.ARMShiftRotate":
        return self.d.get_arm_register_shift(self.args[0])

    def __str__(self):
        return self.get_register() + "," + str(self.get_srt())


class ARMRegBitSequenceOp(ARMOperandKind):

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        ARMOperandKind.__init__(self, d, index, tags, args)


class ARMAbsoluteOp(ARMOperandKind):

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        ARMOperandKind.__init__(self, d, index, tags, args)

    @property
    def address(self) -> "chb.app.BDictionary.AsmAddress":
        return self.d.app.bdictionary.get_address(self.args[0])

    def __str__(self) -> str:
        return str(self.address)


class ARMMemMultipleOp(ARMOperandKind):

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        ARMOperandKind.__init__(self, d, index, tags, args)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def count(self) -> int:
        return self.args[1]

    def __str__(self):
        return self.register


class ARMOffsetAddressOp(ARMOperandKind):

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        ARMOperandKind.__init__(self, d, index, tags, args)

    @property
    def register(self) -> str:
        return self.tags[1]

    def get_memory_offset(self) -> "chb.arm.ARMMemoryOffset.ARMMemoryOffset":
        return self.d.get_arm_memory_offset(self.args[0])

    @property
    def is_add(self) -> bool:
        return self.args[1] == 1

    @property
    def is_write_back(self) -> bool:
        return self.args[2] == 1

    @property
    def is_index(self) -> bool:
        return self.args[3] == 1

    def __str__(self) -> str:
        memoffset = str(self.get_memory_offset())
        if not self.is_add:
            memoffset = "-" + memoffset
        if self.is_write_back:
            if self.is_index:
                return "[" + self.register + "], " + memoffset
            else:
                return "[" + self.register + ", " + memoffset + "]!"
        else:
            return "[" + self.register + ", " + memoffset + "]"


class ARMImmediateOp(ARMOperandKind):

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        ARMOperandKind.__init__(self, d, index, tags, args)

    @property
    def value(self) -> int:
        return int(self.tags[1])

    def to_unsigned_int(self) -> int:
        return self.value

    def to_signed_int(self) -> int:
        return self.value

    def is_arm_immediate(self):
        return True

    def __str__(self) -> str:
        return hex(self.value)
