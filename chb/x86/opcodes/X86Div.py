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

from chb.util.IndexedTable import IndexedTableValue

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode, simplify_result
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.simulation.X86SimulationState import X86SimulationState


@x86registry.register_tag("div", X86Opcode)
class X86Div(X86Opcode):
    """DIV divisor : unsigned divide

    args[0]: width (1 or 4)
    args[1]: index of quotient operand
    args[2]: index of remainder operand
    args[3]: index of dividend operand
    args[4]: index of divisor operand
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def quotient_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[0])

    @property
    def remainder_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[1])

    @property
    def dividend_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[2])

    @property
    def divisor_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[3])

    @property
    def operands(self) -> Sequence[X86Operand]:
        return [
            self.quotient_operand,
            self.remainder_operand,
            self.dividend_operand,
            self.divisor_operand]

    def annotation(self, xdata: InstrXData) -> str:
        """data format: a:vvxxxxxx

        vars[0]: quotient-lhs
        vars[1]: remainder-lhs
        xprs[0]: dividend
        xprs[1]: divisor
        xprs[2]: quotient-rhs (syntactic)
        xprs[3]: quotient-rhs (simplified)
        xprs]4]: remainder-rhs (syntactic)
        xprs[5]: remainder-rhs (simplified)
        """

        lhs1 = str(xdata.vars[0])
        lhs2 = str(xdata.vars[1])
        quot = xdata.xprs[2]
        rquot = xdata.xprs[3]
        rem = xdata.xprs[4]
        rrem = xdata.xprs[5]
        xquot = simplify_result(xdata.args[4], xdata.args[5], quot, rquot)
        xrem = simplify_result(xdata.args[6], xdata.args[7], rem, rrem)
        return lhs1 + ' = ' + xquot + '; ' + lhs2 + ' = ' + xrem

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        return xdata.vars

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs
