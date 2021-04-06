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

import chb.mips.MIPSDictionaryRecord as D
import chb.mips.MIPSOperandKind as K
import chb.mips.MIPSRegister as R
import chb.util.fileutil as UF

from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    import chb.mips.MIPSDictionary


class MIPSOperand(D.MIPSDictionaryRecord):

    def __init__(
            self,
            d: "chb.mips.MIPSDictionary.MIPSDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        D.MIPSDictionaryRecord.__init__(self, d, index, tags, args)
        # args[0]: operand kind

    def get_mips_opkind(self) -> K.MIPSOperandKindBase:
        return self.d.get_mips_opkind(self.args[0])

    def get_size(self) -> int:
        return self.get_mips_opkind().get_size()

    def get_value(self) -> int:
        return self.to_signed_int()

    def is_mips_register(self) -> bool:
        return self.get_mips_opkind().is_mips_register()

    def is_zero_register(self) -> bool:
        return self.is_mips_register() and self.get_mips_register() == 'zero'

    def is_mips_indirect_register(self) -> bool:
        return self.get_mips_opkind().is_mips_indirect_register()

    def is_mips_immediate(self) -> bool:
        return self.get_mips_opkind().is_mips_immediate()

    def is_mips_absolute(self) -> bool:
        return self.get_mips_opkind().is_mips_absolute()

    def is_mips_indirect_register_with_reg(self, reg: str) -> bool:
        return (self.is_mips_indirect_register()
                and str(self.get_mips_indirect_register()) == reg)

    def get_mips_register(self) -> str :
        if self.is_mips_register():
            return self.get_mips_opkind().get_mips_register()
        raise UF.CHBError('Operand is not a register: ' + str(self))

    def get_mips_indirect_register(self) -> str:
        if self.is_mips_indirect_register():
            return self.get_mips_opkind().get_mips_register()
        raise UF.CHBError('Operand is not an indirect register: '  + str(self))

    def get_mips_indirect_register_offset(self) -> int:
        if self.is_mips_indirect_register():
            return self.get_mips_opkind().get_offset()
        raise UF.CHBError('Operand is not an indirect register: ' + str(self))

    def get_mips_absolute_address_value(self) -> int:
        if self.is_mips_absolute():
            return self.get_mips_opkind().get_address().get_int()
        raise UF.CHBError('Operand is not an absolute address: ' + str(self))

    def to_signed_int(self) -> int:
        if self.is_mips_immediate():
            return self.get_mips_opkind().to_signed_int()
        raise UF.CHBError('Operand is not an immediate: ' + str(self))

    def to_unsigned_int(self) -> int:
        if self.is_mips_immediate():
            return self.get_mips_opkind().to_unsigned_int()
        raise UF.CHBError('Operand is not an immediate: ' + str(self))

    def to_expr_string(self) -> str:
        return self.get_mips_opkind().to_expr_string()

    def __str__(self) -> str:
        return str(self.get_mips_opkind())
