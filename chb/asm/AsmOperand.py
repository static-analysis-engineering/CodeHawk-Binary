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

from typing import List, TYPE_CHECKING

import chb.app.Operand as OP
import chb.asm.X86DictionaryRecord as D
import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.asm.X86Dictionary

class AsmOperand(OP.Operand, D.X86DictionaryRecord):
    """X86 assembly instruction operand.

    args[0]: size
    args[1]: operand kind
    """

    def __init__(
            self,
            d: "chb.asm.X86Dictionary.X86Dictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        D.X86DictionaryRecord.__init__(self, d, index, tags, args)
        OP.Operand.__init__(self)

    def get_size(self) -> int:
        return int(self.args[0])

    def get_opkind(self): return self.d.get_opkind(self.args[1])

    def is_register(self) -> bool:
        return self.get_opkind().is_register()

    def is_immediate(self) -> bool:
        return self.get_opkind().is_immediate()

    def is_absolute(self) -> bool:
        return self.get_opkind().is_absolute()

    def get_register(self):
        if self.is_register():
            return self.get_opkind().get_register()
        raise UF.CHBrror('Operand is not a register: ' + str(self))

    def to_operand_string(self) -> str:
        return self.get_opkind().to_operand_string()

    def to_address_string(self) -> str:
        return self.get_opkind().to_address_string()

    def __str__(self) -> str:
        return str(self.get_opkind())
