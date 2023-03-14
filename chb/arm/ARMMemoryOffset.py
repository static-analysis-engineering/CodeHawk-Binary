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

from typing import cast, List, TYPE_CHECKING

from chb.arm.ARMDictionaryRecord import ARMDictionaryRecord, armregistry

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMShiftRotate import ARMShiftRotate, ARMImmSRT


class ARMMemoryOffset(ARMDictionaryRecord):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMDictionaryRecord.__init__(self, d, ixval)

    @property
    def is_immediate(self) -> bool:
        return False

    @property
    def is_index(self) -> bool:
        return False

    @property
    def is_shifted_index(self) -> bool:
        return False

    def ast_rvalue(self, astree: ASTInterface) -> AST.ASTExpr:
        raise UF.CHBError("AST value not defined for " + str(self))

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

    @property
    def is_immediate(self) -> bool:
        return True

    @property
    def is_zero(self) -> bool:
        return self.immediate == 0

    def ast_rvalue(self, astree: ASTInterface) -> AST.ASTExpr:
        return astree.mk_integer_constant(self.immediate)

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

    @property
    def is_index(self) -> bool:
        return True

    def ast_rvalue(self, astree: ASTInterface) -> AST.ASTExpr:
        return astree.mk_register_variable_expr(self.register)

    def __str__(self) -> str:
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

    @property
    def is_shifted_index(self) -> bool:
        return True

    def ast_rvalue(self, astree: ASTInterface) -> AST.ASTExpr:
        srt = self.shift_rotate
        if srt.is_imm_srt and srt.is_shift_left:
            srt = cast("ARMImmSRT", srt)
            rxpr = astree.mk_register_variable_expr(self.register)
            scale = astree.mk_integer_constant(srt.shift_amount)
            return astree.mk_binary_op("lsl", rxpr, scale)
        else:
            raise UF.CHBError(
                "shifted-index-offset not yet supported for " + str(self))

    def __str__(self) -> str:
        srt = str(self.shift_rotate)
        if srt == "":
            return self.register
        else:
            return self.register + "," + srt
