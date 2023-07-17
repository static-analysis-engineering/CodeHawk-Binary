# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2023 Aarno Labs LLC
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


@x86registry.register_tag("dec", X86Opcode)
class X86Dec(X86Opcode):
    """DEC op

    args[0]: index of operand in x86dictionary
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
        """data format: a:vxxx .

        vars[0]: dst
        xprs[0]: src
        xprs[1]: src - 1 (syntactic)
        xprs[2]: src - 1 (simplified)
        """

        lhs = str(xdata.vars[0])
        rhs = xdata.xprs[1]
        rrhs = xdata.xprs[2]
        xrhs = simplify_result(xdata.args[2], xdata.args[3], rhs, rrhs)
        return lhs + ' = ' + xrhs

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        return [xdata.vars[0]]

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return [xdata.xprs[2]]

    # --------------------------------------------------------------------------
    # Subtracts 1 from the destination operand, while preserving the state of
    # the CF flag.
    #
    # Flags affected:
    # The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set
    # according to the result.
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        op = self.operand
        srcval = simstate.get_rhs(iaddr, op)
        decval = SV.mk_simvalue(1, size=op.size)
        if srcval.is_literal and srcval.is_doubleword:
            srcval = cast(SV.SimDoubleWordValue, srcval)
            newval = srcval.sub(decval)
            simstate.set(iaddr, op, newval)
            simstate.update_flag(iaddr, 'OF', srcval.sub_overflows(decval))
            simstate.update_flag(iaddr, 'ZF', newval.is_zero)
            simstate.update_flag(iaddr, 'SF', newval.is_negative)
            simstate.update_flag(iaddr, 'PF', newval.is_odd_parity)
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ("Decrement not yet supported for "
                 + str(op)
                 + ":"
                 + str(srcval)))
