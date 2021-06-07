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

import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

from chb.util.IndexedTable import IndexedTableValue

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.simulation.X86SimulationState import X86SimulationState


@x86registry.register_tag("test", X86Opcode)
class X86Test(X86Opcode):
    """TEST op1, op2

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
        """data format: a:xx

        xprs[0]: value of op1
        xprs[1]: value op op2
        """

        rhs1 = str(xdata.xprs[0])
        rhs2 = str(xdata.xprs[1])
        return 'test ' + rhs1 + ', ' + rhs2

    # --------------------------------------------------------------------------
    # Computes the bit-wise logical AND of first operand (source 1 operand) and
    # the second operand (source 2 operand) and sets the SF, ZF, and PF status
    # flags according to the result. The result is then discarded.
    #
    # Flags affected:
    # The OF and CF flags are set to 0. The SF, ZF, and PF flags are set according
    # to the result
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        op1 = self.operand_1
        op2 = self.operand_2
        opval1 = simstate.get_rhs(iaddr, op1)
        opval2 = simstate.get_rhs(iaddr, op2)
        if opval1.is_literal and opval1.is_defined:
            opval1 = cast(SV.SimLiteralValue, opval1)
            testresult = opval1.bitwise_and(opval2)
            simstate.clear_flag(iaddr, 'OF')
            simstate.clear_flag(iaddr, 'CF')
            simstate.update_flag(iaddr, 'SF', testresult.is_negative)
            simstate.update_flag(iaddr, 'ZF', testresult.is_zero)
            simstate.update_flag(iaddr, 'PF', testresult.is_odd_parity)
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "Test not applicable to " + str(opval1))
