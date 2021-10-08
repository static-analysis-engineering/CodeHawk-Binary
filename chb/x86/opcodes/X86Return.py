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

from chb.app.InstrXData import InstrXData

from chb.invariants.XXpr import XXpr

import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

from chb.util.IndexedTable import IndexedTableValue

import chb.util.fileutil as UF

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode, simplify_result
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.simulation.X86SimulationState import X86SimulationState


@x86registry.register_tag("ret", X86Opcode)
class X86Return(X86Opcode):
    """RET.

    args[0]: number of bytes popped, otherwise absent
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    def is_return(self) -> bool:
        return True

    @property
    def bytes_popped(self) -> int:
        if len(self.args) == 1:
            return self.args[0]
        else:
            return 0

    def get_return_expr(self, xdata: InstrXData) -> XXpr:
        return xdata.xprs[1]

    def operands(self) -> List[X86Operand]:
        return []

    def annotation(self, xdata: InstrXData) -> str:
        """data format a:xx .

        xprs[0]: value of eax
        xprs[1]: value of eax simplified
        """

        eax = xdata.xprs[0]
        reax = xdata.xprs[1]
        xeax = simplify_result(xdata.args[0], xdata.args[1], eax, reax)
        popped = self.bytes_popped
        if popped == 0:
            return 'return (' + xeax + ')'
        else:
            return "return (" + xeax + ") (adj: " + str(popped) + ")"

    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        raise SU.CHBSimFunctionReturn(iaddr)
