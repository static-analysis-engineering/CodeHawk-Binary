# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs LLC
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
"""Different ways arm operands can be rotated.

Corresponds to arm_register_shift_rotate_t in bchlibarm32/bCHARMTypes:

                                                   tags[0]   tags   args
type register_shift_rotate_t =
  | ARMImmSRT of shift_rotate_type_t * int           "i"       2      1
      (* immediate shift amount *)
  | ARMRegSRT of shift_rotate_type_t * arm_reg_t     "r"       3      0
      (* shift amount in reg *)

and
                                 tag
type shift_rotate_type_t =
  | SRType_LSL                  "LSL"
  | SRType_LSR                  "LSR"
  | SRType_ASR                  "ASR"
  | SRType_ROR                  "ROR"
  | SRType_RRX                  "RRX"

"""

from typing import List, TYPE_CHECKING

from chb.arm.ARMDictionaryRecord import ARMDictionaryRecord, armregistry

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.arm.ARMDictionary


class ARMShiftRotate(ARMDictionaryRecord):

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMDictionaryRecord.__init__(self, d, ixval)

    @property
    def is_imm_srt(self) -> bool:
        return False

    @property
    def is_reg_srt(self) -> bool:
        return False

    @property
    def shift_rotate_type(self) -> str:
        return self.tags[1]

    @property
    def is_shift_left(self) -> bool:
        return self.shift_rotate_type == "LSL"

    @property
    def is_logical_shift_right(self) -> bool:
        return self.shift_rotate_type == "LSR"

    @property
    def is_arithmetic_shift_right(self) -> bool:
        return self.shift_rotate_type == "ASR"

    @property
    def is_rotate_right(self) -> bool:
        return self.shift_rotate_type == "ROR"

    @property
    def is_rotate_right_extend(self) -> bool:
        return self.shift_rotate_type == "RRX"

    def __str__(self) -> str:
        return "shift-rotate: " + self.tags[0]


@armregistry.register_tag("i", ARMShiftRotate)
class ARMImmSRT(ARMShiftRotate):
    """Immediate shift amount.

    tags[1]: shift-rotate type
    args[0]: amount to be shifted (integer)
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMShiftRotate.__init__(self, d, ixval)

    @property
    def is_imm_srt(self) -> bool:
        return True

    @property
    def shift_amount(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        srt = self.shift_rotate_type
        sam = self.shift_amount
        if srt == "LSL" and sam == 0:
            return ""
        else:
            return srt + "#" + str(sam)


@armregistry.register_tag("r", ARMShiftRotate)
class ARMRegSRT(ARMShiftRotate):
    """Amount to be shifted in register.

    tags[1]: shift-rotate type
    tags[2]: register that holds shift amount
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMShiftRotate.__init__(self, d, ixval)

    @property
    def is_reg_srt(self) -> bool:
        return True

    @property
    def register(self) -> str:
        return self.tags[2]

    def __str__(self) -> str:
        return self.shift_rotate_type + " " + self.register
