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
"""Different types of operand of an ARM assembly instruction.

Corresponds to arm_operand_kind_t in bchlibarm32/BCHARMTypes

                                                    tags[0]   tags         args
type arm_operand_kind_t =
  | ARMDMBOption of dmb_option_t                      "d"       2            0
  | ARMReg of arm_reg_t                               "r"       2            0
  | ARMRegList of arm_reg_t list                      "l"     1+len(regs)    0
  | ARMShiftedReg of                                  "s"       2            1
     arm_reg_t
     * register_shift_rotate_t
  | ARMRegBitSequence of arm_reg_t * int * int        "b"       2            2
     (* lsb, widthm1 *)
  | ARMImmediate of immediate_int                     "i"       2            0
  | ARMAbsolute of doubleword_int                     "a"       1            1
  | ARMMemMultiple of arm_reg_t * int                 "m"       2            1
     (* number of locations *)
  | ARMOffsetAddress of                               "o"       2            4
      arm_reg_t  (* base register *)
      * arm_memory_offset_t (* offset *)
      * bool (* isadd *)
      * bool (* iswback *)
      * bool (* isindex *)
"""

from typing import List, TYPE_CHECKING

from chb.arm.ARMDictionaryRecord import ARMDictionaryRecord, armregistry

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.app.BDictionary import BDictionary, AsmAddress
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMMemoryOffset import ARMMemoryOffset
    from chb.arm.ARMShiftRotate import ARMShiftRotate


class ARMOperandKind(ARMDictionaryRecord):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMDictionaryRecord.__init__(self, d, ixval)

    @property
    def is_arm_absolute(self) -> bool:
        return False

    @property
    def is_arm_immediate(self) -> bool:
        return False

    def __str__(self) -> str:
        return "operandkind: " + self.tags[0]


@armregistry.register_tag("r", ARMOperandKind)
class ARMRegisterOp(ARMOperandKind):
    """Regular register.

    tags[1]: name of register
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return self.register


@armregistry.register_tag("l", ARMOperandKind)
class ARMRegListOp(ARMOperandKind):
    """List of regular registers.

    tags[1...]: names of registers
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def registers(self) -> List[str]:
        return self.tags[1:]

    def __str__(self) -> str:
        return "{" + ",".join(self.registers) + "}"


@armregistry.register_tag("s", ARMOperandKind)
class ARMShiftedRegisterOp(ARMOperandKind):
    """Value of register shifted by a certain amount.

    tags[1]: name of register
    args[0]: index of register-shift-rotate in armdictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def shift_rotate(self) -> "ARMShiftRotate":
        return self.armd.arm_register_shift(self.args[0])

    def __str__(self) -> str:
        return self.register + "," + str(self.shift_rotate)


@armregistry.register_tag("b", ARMOperandKind)
class ARMRegBitSequenceOp(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)


@armregistry.register_tag("a", ARMOperandKind)
class ARMAbsoluteOp(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def address(self) -> "AsmAddress":
        return self.bd.address(self.args[0])

    def __str__(self) -> str:
        return str(self.address)


@armregistry.register_tag("m", ARMOperandKind)
class ARMMemMultipleOp(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def count(self) -> int:
        return self.args[1]

    def __str__(self) -> str:
        return self.register


@armregistry.register_tag("o", ARMOperandKind)
class ARMOffsetAddressOp(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def memory_offset(self) -> "ARMMemoryOffset":
        return self.armd.arm_memory_offset(self.args[0])

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
        memoffset = str(self.memory_offset)
        if not self.is_add:
            memoffset = "-" + memoffset
        if self.is_write_back:
            if self.is_index:
                return "[" + self.register + "], " + memoffset
            else:
                return "[" + self.register + ", " + memoffset + "]!"
        else:
            return "[" + self.register + ", " + memoffset + "]"


@armregistry.register_tag("i", ARMOperandKind)
class ARMImmediateOp(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def value(self) -> int:
        return int(self.tags[1])

    def to_unsigned_int(self) -> int:
        return self.value

    def to_signed_int(self) -> int:
        return self.value

    @property
    def is_arm_immediate(self) -> bool:
        return True

    def __str__(self) -> str:
        return hex(self.value)
