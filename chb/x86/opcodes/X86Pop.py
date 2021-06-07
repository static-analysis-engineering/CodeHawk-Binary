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

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode, simplify_result
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.simulation.X86SimulationState import X86SimulationState


@x86registry.register_tag("pop", X86Opcode)
class X86Pop(X86Opcode):
    """POP op

    args[0]: number of bytes to be popped
    args[1]: index of op in x86dictionary
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def size(self) -> int:
        return int(self.args[0])

    @property
    def dst_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[1])

    @property
    def get_operands(self) -> Sequence[X86Operand]:
        return [self.dst_operand]

    def annotation(self, xdata: InstrXData) -> str:
        """data format
             a:v, restore  : restore initial value of register
             a:vxxx  otherwise

        vars[0]: dst
        xprs[0]: rhs
        xprs[1]: esp
        xprs[2]: esp (simplified)
        """

        if len(xdata.tags) == 2 and xdata.tags[1] == "restore":
            return "restore " + str(xdata.vars[0])
        else:
            lhs = str(xdata.vars[0])
            rhs = xdata.xprs[0]
            esp = xdata.xprs[1]
            resp = xdata.xprs[2]
            xresp = simplify_result(xdata.args[2], xdata.args[3], esp, resp)
            return lhs + ' = ' + str(rhs) + '; esp = ' + xresp

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        return [xdata.vars[0]]

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        if len(xdata.xprs) == 3:
            return [xdata.xprs[2]]
        else:
            return []

    # --------------------------------------------------------------------------
    # Loads the value from the top of the stack to the location specified with
    # the destination operand (or explicit opcode) and then increments the stack
    # pointer. The destination operand can be a general-purpose register,
    # memory location, or segment register.
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        srcval = simstate.pop_value(iaddr)
        simstate.set(iaddr, self.dst_operand, srcval)
