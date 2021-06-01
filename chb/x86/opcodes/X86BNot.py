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

from typing import cast, List, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

from chb.x86.simulation.X86SimulationState import X86SimulationState

from chb.util.IndexedTable import IndexedTableValue

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode, simplify_result
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.simulation.X86SimulationState import X86SimulationState


@x86registry.register_tag("not", X86Opcode)
class X86BNot(X86Opcode):
    """one's complement negate, flip all bits

    args[0]: index of operand in x86dictionary
    """
    
    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def operand(self) -> X86Operand:
        return self.x86d.get_operand(self.args[0])

    def get_operands(self) -> List[X86Operand]:
        return [self.operand]

    def get_annotation(self, xdata: InstrXData) -> str:
        """data format: a:vxxx .

        vars[0]: dst-lhs
        xprs[0]: dst-rhs
        xprs[1]: not dst-rhs (syntactic)
        xprs[2]: not dst-rhs (simplified)
        """
        
        lhs = str(xdata.vars[0])
        rhsx = xdata.xprs[1]
        rrhsx = xdata.xprs[2]
        xrhs = simplify_result(xdata.args[2], xdata.args[3], rhsx, rrhsx)
        return lhs + ' = ' +  xrhs

    def get_lhs(self, xdata: InstrXData) -> List[XVariable]:
        return [xdata.vars[0]]

    def get_rhs(self, xdata: InstrXData) -> List[XXpr]:
        return [xdata.xprs[3]]

    # --------------------------------------------------------------------------
    # Performs a bitwise NOT operation (each 1 is set to 0, and each 0 is set
    # to 1) on the destination operand and stores the result in the destination
    # operand location.
    #
    # Flags affected: None
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        op = self.operand
        srcval = simstate.get_rhs(iaddr, op)
        if srcval.is_doubleword() and srcval.is_literal():
            srcval = cast(SV.SimDoubleWordValue, srcval)
            simstate.set(iaddr,op,srcval.bitwise_not())
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "bitwise-not not yet supported for " + str(op) + ":" + str(srcval))

