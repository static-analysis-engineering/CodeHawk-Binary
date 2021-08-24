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
"""Operand of MIPS assembly instruction."""

from chb.app.Operand import Operand

from chb.mips.MIPSDictionaryRecord import MIPSDictionaryRecord
from chb.mips.MIPSOperandKind import MIPSOperandKind
from chb.mips.MIPSRegister import MIPSRegister

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    import chb.mips.MIPSDictionary


class MIPSOperand(Operand, MIPSDictionaryRecord):
    """MIPS assembly instruction operand.

    args[0]: index of operand kind in mips dictionary
    """

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSDictionaryRecord.__init__(self, d, ixval)
        Operand.__init__(self)

    @property
    def opkind(self) -> MIPSOperandKind:
        return self.mipsd.mips_opkind(self.args[0])

    @property
    def size(self) -> int:
        return self.opkind.size

    @property
    def value(self) -> int:
        return self.to_signed_int()

    @property
    def is_mips_register(self) -> bool:
        return self.opkind.is_mips_register

    @property
    def is_register(self) -> bool:
        return self.opkind.is_mips_register

    @property
    def is_zero_register(self) -> bool:
        return self.is_mips_register and self.register == 'zero'

    @property
    def is_mips_indirect_register(self) -> bool:
        return self.opkind.is_mips_indirect_register

    @property
    def is_indirect_register(self) -> bool:
        return self.opkind.is_mips_indirect_register

    @property
    def offset(self) -> int:
        return self.opkind.offset

    @property
    def is_mips_immediate(self) -> bool:
        return self.opkind.is_mips_immediate

    @property
    def is_immediate(self) -> bool:
        return self.opkind.is_mips_immediate

    @property
    def is_mips_absolute(self) -> bool:
        return self.opkind.is_mips_absolute

    def is_mips_indirect_register_with_reg(self, reg: str) -> bool:
        return (self.is_mips_indirect_register
                and str(self.indirect_register) == reg)

    @property
    def register(self) -> str:
        if self.is_mips_register:
            return self.opkind.register
        raise UF.CHBError('Operand is not a register: ' + str(self))

    @property
    def indirect_register(self) -> str:
        if self.is_mips_indirect_register:
            return self.opkind.register
        raise UF.CHBError(
            'Operand is not an indirect register: ' + str(self))

    @property
    def indirect_register_offset(self) -> int:
        if self.is_mips_indirect_register:
            return self.opkind.offset
        raise UF.CHBError('Operand is not an indirect register: ' + str(self))

    @property
    def absolute_address_value(self) -> int:
        if self.is_mips_absolute:
            return self.opkind.address.get_int()
        raise UF.CHBError('Operand is not an absolute address: ' + str(self))

    def to_signed_int(self) -> int:
        if self.is_mips_immediate:
            return self.opkind.to_signed_int()
        raise UF.CHBError('Operand is not an immediate: ' + str(self))

    def to_unsigned_int(self) -> int:
        if self.is_mips_immediate:
            return self.opkind.to_unsigned_int()
        raise UF.CHBError('Operand is not an immediate: ' + str(self))

    def to_expr_string(self) -> str:
        return self.opkind.to_expr_string()

    def __str__(self) -> str:
        return str(self.opkind)
