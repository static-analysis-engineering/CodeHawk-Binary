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
"""Represents the different kinds of assembly instruction operands.

Corresponds to mips_operand_kind_t in bchlibmips32/BCHMIPSTypes

                                               tags[0]   tags    args
type mips_operand_kind_t =
  | MIPSReg of mips_reg_t                        "r"       2       0
  | MIPSSpecialReg of mips_special_reg_t         "s"       2       0
  | MIPSFPReg of int                             "f"       1       1
  | MIPSIndReg of mips_reg_t * numerical_t       "i"       3       0
  | MIPSAbsolute of doubleword_int               "a"       1       1
  | MIPSImmediate of immediate_int               "m"       2       0

"""
from typing import List, TYPE_CHECKING

from chb.app.BDictionary import BDictionary, AsmAddress

from chb.mips.MIPSDictionaryRecord import MIPSDictionaryRecord, mipsregistry

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.mips.MIPSDictionary


class MIPSOperandKind(MIPSDictionaryRecord):

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSDictionaryRecord.__init__(self, d, ixval)

    @property
    def is_mips_absolute(self) -> bool:
        return False

    @property
    def is_mips_immediate(self) -> bool:
        return False

    @property
    def is_mips_indirect_register(self) -> bool:
        return False

    @property
    def is_mips_register(self) -> bool:
        return False

    @property
    def is_mips_special_register(self) -> bool:
        return False

    @property
    def size(self) -> int:
        raise UF.CHBError(
            "Size undefined for operand kind: " + self.__str__())

    @property
    def register(self) -> str:
        raise UF.CHBError(
            "Register undefined for operand kind: " + self.__str__())

    @property
    def offset(self) -> int:
        raise UF.CHBError(
            "Operand kind does not have an offset: " + self.__str__())

    @property
    def address(self) -> AsmAddress:
        raise UF.CHBError(
            "Operand kind does not have an address: " + self.__str__())

    @property
    def value(self) -> int:
        raise UF.CHBError(
            "Operand kind does not have a value: " + self.__str__())

    def to_unsigned_int(self) -> int:
        raise UF.CHBError(
            "Operand kind cannot be converted to int: " + self.__str__())

    def to_signed_int(self) -> int:
        raise UF.CHBError(
            "Operand kind cannot be converted to int: " + self.__str__())

    def to_expr_string(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return 'operandkind:' + self.tags[0]


@mipsregistry.register_tag("r", MIPSOperandKind)
class MIPSRegisterOp(MIPSOperandKind):

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOperandKind.__init__(self, d, ixval)

    @property
    def is_mips_register(self) -> bool:
        return True

    @property
    def size(self) -> int:
        return 4

    @property
    def register(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return str(self.register)


@mipsregistry.register_tag("s", MIPSOperandKind)
class MIPSSpecialRegisterOp(MIPSOperandKind):

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOperandKind.__init__(self, d, ixval)

    @property
    def is_mips_register(self) -> bool:
        return True

    @property
    def is_mips_special_register(self) -> bool:
        return True

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def size(self) -> int:
        return 4

    def __str__(self) -> str:
        return str(self.register)


@mipsregistry.register_tag("i", MIPSOperandKind)
class MIPSIndirectRegisterOp(MIPSOperandKind):

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOperandKind.__init__(self, d, ixval)

    @property
    def is_mips_indirect_register(self) -> bool:
        return True

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def offset(self) -> int:
        return int(self.tags[2])

    @property
    def size(self) -> int:
        return 4

    def to_expr_string(self) -> str:
        if self.offset == 0:
            return '*(' + str(self.register + ')')
        else:
            return (
                '*('
                + str(self.register)
                + ' + '
                + str(self.offset) + ')')

    def __str__(self) -> str:
        return str(self.offset) + '(' + str(self.register) + ')'


@mipsregistry.register_tag("m", MIPSOperandKind)
class MIPSImmediateOp(MIPSOperandKind):

    def __init__(self,
                 d: "chb.mips.MIPSDictionary.MIPSDictionary",
                 ixval: IndexedTableValue) -> None:
        MIPSOperandKind.__init__(self, d, ixval)

    @property
    def is_mips_immediate(self) -> bool:
        return True

    @property
    def value(self) -> int:
        return int(self.tags[1])

    def to_unsigned_int(self) -> int:
        return self.value

    def to_signed_int(self) -> int:
        return self.value

    def __str__(self) -> str:
        return str(hex(self.value))


@mipsregistry.register_tag("a", MIPSOperandKind)
class MIPSAbsoluteOp(MIPSOperandKind):

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOperandKind.__init__(self, d, ixval)

    @property
    def address(self) -> AsmAddress:
        return self.bd.address(self.args[0])

    @property
    def is_mips_absolute(self) -> bool:
        return True

    def __str__(self) -> str:
        return str(self.address)


@mipsregistry.register_tag("f", MIPSOperandKind)
class MIPSFloatingPointRegisterOp(MIPSOperandKind):

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOperandKind.__init__(self, d, ixval)

    @property
    def register_index(self) -> int:
        return int(self.args[0])

    @property
    def is_mips_floating_point_register(self) -> bool:
        return True

    def __str__(self) -> str:
        return 'FP(' + str(self.register_index) + ')'
