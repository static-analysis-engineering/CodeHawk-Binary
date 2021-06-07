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

from typing import cast, List, Sequence, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.simulation.X86SimulationState import X86SimulationState


@x86registry.register_tag("xchg", X86Opcode)
class X86Xchg(X86Opcode):
    """XCHG op1, op2

    args[0]: index of op1 in x86dictionary
    args[1]: index of op2 in x86dictionary
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def operand_1(self) -> X86Operand:
        return self.x86d.operand(self.args[0])

    @property
    def operand_2(self) -> X86Operand:
        return self.x86d.operand(self.args[1])

    @property
    def operands(self) -> Sequence[X86Operand]:
        return [self.operand_1, self.operand_2]

    def annotation(self, xdata: InstrXData) -> str:
        """data format: 'nop', or a:vvxx .

        vars[0]: lhs1
        vars[1]: lhs2
        xprs[0]: rhs1
        xprs[1]: rhs2
        """
        if len(xdata.tags) == 1 and xdata.tags[0] == "nop":
            return "nop"
        else:
            lhs1 = str(xdata.vars[0])
            lhs2 = str(xdata.vars[1])
            rhs1 = str(xdata.xprs[0])
            rhs2 = str(xdata.xprs[1])
            return (lhs1 + ' = ' + rhs2 + '; ' + lhs2 + ' = ' + rhs1)

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        return xdata.vars

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    # --------------------------------------------------------------------------
    # Exchanges the contents of the destination (first) and source (second)
    # operands.
    #
    # Flags affected: None
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        op1 = self.operand_1
        op2 = self.operand_2
        val1 = simstate.get_rhs(iaddr, op1)
        val2 = simstate.get_rhs(iaddr, op2)
        simstate.set(iaddr, op1, val2)
        simstate.set(iaddr, op2, val1)
