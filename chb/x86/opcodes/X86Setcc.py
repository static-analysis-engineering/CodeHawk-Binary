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

from typing import List, Sequence, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode
from chb.x86.X86Operand import X86Operand

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary


@x86registry.register_tag("seta", X86Opcode)
@x86registry.register_tag("setbe", X86Opcode)
@x86registry.register_tag("setc", X86Opcode)
@x86registry.register_tag("setg", X86Opcode)
@x86registry.register_tag("setge", X86Opcode)
@x86registry.register_tag("setl", X86Opcode)
@x86registry.register_tag("setle", X86Opcode)
@x86registry.register_tag("setnc", X86Opcode)
@x86registry.register_tag("setno", X86Opcode)
@x86registry.register_tag("setns", X86Opcode)
@x86registry.register_tag("setnz", X86Opcode)
@x86registry.register_tag("seto", X86Opcode)
@x86registry.register_tag("seta", X86Opcode)
@x86registry.register_tag("setpe", X86Opcode)
@x86registry.register_tag("setpo", X86Opcode)
@x86registry.register_tag("sets", X86Opcode)
@x86registry.register_tag("setz", X86Opcode)
class X86Setcc(X86Opcode):
    """SET<cc> op.

    args[0]: index of op in x86dictionary
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def operand(self) -> X86Operand:
        return self.x86d.operand(self.args[0])

    @property
    def operands(self) -> Sequence[X86Operand]:
        return [self.operand]

    def annotation(self, xdata: InstrXData) -> str:
        """data format: a:vx

        vars[0]: lhs
        xprs[0]: rhs
        """

        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[0])
        return lhs + ' = ' + rhs
