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
from chb.x86.X86Opcode import X86Opcode, simplify_result
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.simulation.X86SimulationState import X86SimulationState


@x86registry.register_tag("neg", X86Opcode)
class X86Negate(X86Opcode):
    """NEG op .

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

    # xdata: [ "a:vxxx" ],[ lhs, rhs, rhs-operation, rhs-operation-simplified ]
    def annotation(self, xdata: InstrXData) -> str:
        """data format: a:vxxx

        vars[0]: lhs
        xprs[0]: rhs
        xprs[1]: rhs 2's complement (syntactic)
        xprs[2]: rhs 2's complement (simplified)
        """

        lhs = str(xdata.vars[0])
        rhsx = xdata.xprs[1]
        rrhsx = xdata.xprs[2]
        xrhs = simplify_result(xdata.args[2], xdata.args[3], rhsx, rrhsx)
        return lhs + ' = ' + xrhs

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        return [xdata.vars[0]]

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return [xdata.xprs[2]]

    # --------------------------------------------------------------------------
    # Replaces the value of operand (the destination operand) with its two's
    # complement. (This operation is equivalent to subtracting the operand from
    # 0.)
    #
    # Flags affected:
    # The CF flag set to 0 if the source operand is 0; otherwise it is set to 1.
    # The OF, SF, ZF, AF, and PF flags are set according to the result.
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        op = self.operand
        srcval = simstate.get_rhs(iaddr, op)
        zero = SV.mk_simvalue(0, op.size)
        if zero.is_doubleword and srcval.is_doubleword and srcval.is_literal:
            zero = cast(SV.SimDoubleWordValue, zero)
            srcval = cast(SV.SimDoubleWordValue, srcval)
            result = zero.sub(srcval)
            simstate.set(iaddr, op, result)
            if srcval.is_zero:
                simstate.set_flag(iaddr, 'CF')
            else:
                simstate.clear_flag(iaddr, 'CF')
            simstate.update_flag(iaddr, 'OF', zero.sub_overflows(srcval))
            simstate.update_flag(iaddr, 'SF', result.is_negative)
            simstate.update_flag(iaddr, 'ZF', result.is_zero)
            simstate.update_flag(iaddr, 'PF', result.is_odd_parity)
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "Negation of " + str(op) + ":" + str(result) + " not yet supported")
