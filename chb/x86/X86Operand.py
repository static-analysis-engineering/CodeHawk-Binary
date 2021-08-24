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
"""Operand of x86 assembly instruction."""

from typing import cast, List, TYPE_CHECKING

from chb.app.Operand import Operand

from chb.x86.X86DictionaryRecord import X86DictionaryRecord
from chb.x86.X86OperandKind import (
    X86OperandKind, X86RegisterOp, X86ImmediateOp, X86IndirectRegisterOp)

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.x86.X86Dictionary


class X86Operand(Operand, X86DictionaryRecord):
    """X86 assembly instruction operand.

    args[0]: size
    args[1]: operand kind
    """

    def __init__(
            self,
            d: "chb.x86.X86Dictionary.X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86DictionaryRecord.__init__(self, d, ixval)
        Operand.__init__(self)
        self.check_key(1, 2, "X86Operand")

    @property
    def size(self) -> int:
        return self.args[0]

    @property
    def value(self) -> int:
        return self.to_signed_int()

    @property
    def opkind(self) -> X86OperandKind:
        return self.x86d.opkind(self.args[1])

    @property
    def is_register(self) -> bool:
        return self.opkind.is_register

    @property
    def is_indirect_register(self) -> bool:
        return self.opkind.is_indirect_register

    @property
    def indirect_register(self) -> str:
        if self.is_indirect_register:
            return cast(X86IndirectRegisterOp, self.opkind).register
        else:
            raise UF.CHBError("Operand is not an indirect register: " + str(self))

    @property
    def offset(self) -> int:
        return self.opkind.offset

    @property
    def is_immediate(self) -> bool:
        return self.opkind.is_immediate

    @property
    def is_absolute(self) -> bool:
        return self.opkind.is_absolute

    @property
    def register(self) -> str:
        if self.is_register:
            return cast(X86RegisterOp, self.opkind).register
        else:
            raise UF.CHBError('Operand is not a register: ' + str(self))

    def to_signed_int(self) -> int:
        if self.is_immediate:
            opkind = cast(X86ImmediateOp, self.opkind)
            return opkind.value
        else:
            raise UF.CHBError("Operand is not an immediate: " + str(self))

    def to_operand_string(self) -> str:
        return self.opkind.to_operand_string()

    def to_address_string(self) -> str:
        return self.opkind.to_address_string()

    def __str__(self) -> str:
        return str(self.opkind)
