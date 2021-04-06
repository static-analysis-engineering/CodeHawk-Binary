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

from typing import List, TYPE_CHECKING

import chb.app.BDictionary as B
import chb.mips.MIPSDictionaryRecord as D
import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.mips.MIPSDictionary

class MIPSOperandKindBase(D.MIPSDictionaryRecord):

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        D.MIPSDictionaryRecord.__init__(self, d, index, tags, args)
        self.bd = self.d.app.bdictionary

    def is_mips_absolute(self) -> bool:
        return False

    def is_mips_immediate(self) -> bool:
        return False

    def is_mips_indirect_register(self) -> bool:
        return False

    def is_mips_register(self) -> bool:
        return False

    def is_mips_special_register(self) -> bool:
        return False

    def get_size(self) -> int:
        raise UF.CHBError(
            "Size undefined for operand kind: " + self.__str__())

    def get_mips_register(self) -> str:
        raise UF.CHBError(
            "Register undefined for operand kind: " + self.__str__())

    def get_offset(self) -> int:
        raise UF.CHBError(
            "Operand kind does not have an offset: " + self.__str__())

    def get_address(self) -> B.AsmAddress:
        raise UF.CHBError(
            "Operand kind does not have an address: " + self.__str__())

    def get_value(self) -> int:
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


class MIPSRegisterOp(MIPSOperandKindBase):

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        MIPSOperandKindBase.__init__(self, d, index, tags, args)

    def is_mips_register(self) -> bool:
        return True

    def get_size(self) -> int:
        return 4

    def get_mips_register(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return str(self.get_mips_register())


class MIPSSpecialRegisterOp(MIPSOperandKindBase):

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        MIPSOperandKindBase.__init__(self, d, index, tags, args)

    def is_mips_special_register(self) -> bool:
        return True

    def get_mips_register(self) -> str:
        return self.tags[1]

    def get_size(self) -> int:
        return 4

    def __str__(self) -> str:
        return str(self.get_mips_register())


class MIPSIndirectRegisterOp(MIPSOperandKindBase):

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        MIPSOperandKindBase.__init__(self, d, index, tags, args)

    def is_mips_indirect_register(self) -> bool:
        return True

    def get_mips_register(self) -> str:
        return self.tags[1]

    def get_offset(self) -> int:
        return int(self.tags[2])

    def get_size(self) -> int:
        return 4

    def to_expr_string(self) -> str:
        if self.get_offset() == 0:
            return '*(' + str(self.get_mips_register() + ')' )
        else:
            return (
                '*('
                + str(self.get_mips_register())
                + ' + '
                + str(self.get_offset()) + ')')

    def __str__(self) -> str:
        return str(self.get_offset()) + '(' + str(self.get_mips_register()) + ')'


class MIPSImmediateOp(MIPSOperandKindBase):

    def __init__(self,
                 d: "chb.mips.MIPSDictionary.MIPSDictionary",
                 index: int,
                 tags: List[str],
                 args: List[int]) -> None:
        MIPSOperandKindBase.__init__(self, d, index, tags, args)

    def is_mips_immediate(self) -> bool:
        return True

    def get_value(self) -> int:
        return int(self.tags[1])

    def to_unsigned_int(self) -> int:
        return self.get_value()

    def to_signed_int(self) -> int:
        return self.get_value()

    def __str__(self) -> str:
        return str(hex(self.get_value()))


class MIPSAbsoluteOp(MIPSOperandKindBase):

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        MIPSOperandKindBase.__init__(self, d, index, tags, args)

    def get_address(self) -> B.AsmAddress:
        return self.bd.get_address(self.args[0])

    def is_mips_absolute(self) -> bool:
        return True

    def __str__(self) -> str:
        return str(self.get_address())


class MIPSFloatingPointRegisterOp(MIPSOperandKindBase):

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        MIPSOperandKindBase.__init__(self, d, index, tags, args)

    def get_register_index(self) -> int:
        return int(self.args[0])

    def is_mips_floating_point_register(self) -> bool:
        return True

    def __str__(self) -> str:
        return 'FP(' + str(self.get_register_index()) + ')'
