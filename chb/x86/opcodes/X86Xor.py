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


@x86registry.register_tag("xor", X86Opcode)
class X86Xor(X86Opcode):
    """XOR dst, src

    args[0]: index of dst in x86dictionary
    args[1]: index of src in x86dictionary
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def src_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[1])

    @property
    def dst_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[0])

    @property
    def operands(self) -> Sequence[X86Operand]:
        return [self.dst_operand, self.src_operand]

    def annotation(self, xdata: InstrXData) -> str:
        """"data format: a:vxxxx

        vars[0]: lhs
        xprs[0]: rhs1
        xprs[1]: rhs2
        xprs[2]: rhs1 xor rhs2 (syntactic)
        xprs[3]: rhs1 xor rhs2 (simplified)
        """

        if len(xdata.xprs) == 0:       # src, dst are the same, result is zero
            lhs = str(xdata.vars[0])
            return lhs + ' = 0'

        else:
            lhs = str(xdata.vars[0])
            result = xdata.xprs[2]
            rresult = xdata.xprs[3]
            xresult = simplify_result(xdata.args[3], xdata.args[4], result, rresult)
            return lhs + ' = ' + xresult

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        return xdata.vars

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    # --------------------------------------------------------------------------
    # Performs a bitwise exclusive OR (XOR) operation on the destination (first)
    # and source (second) operands and stores the result in the destination
    # operand location.
    # Each bit of the result is 1 if the corresponding bits of the operands are
    # different; each bit is 0 if the corresponding bits are the same.
    #
    # Flags affected:
    # The OF and CF flags are cleared; the SF, ZF, and PF flags are set according
    # to the result. The state of the AF flag is undefined.
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        srcop = self.src_operand
        dstop = self.dst_operand
        if (
                srcop.is_register
                and dstop.is_register
                and srcop.register == dstop.register):
            simstate.set(iaddr, dstop, SV.simZero)
            simstate.set_flag(iaddr, 'ZF')
            simstate.clear_flag(iaddr, 'PF')
            simstate.clear_flag(iaddr, 'CF')
            simstate.clear_flag(iaddr, 'OF')
            simstate.clear_flag(iaddr, 'SF')
        else:
            srcval = simstate.get_rhs(iaddr, srcop)
            dstval = simstate.get_rhs(iaddr, dstop)
            if dstval.is_literal:
                dstval = cast(SV.SimLiteralValue, dstval)
                result = dstval.bitwise_xor(srcval)
                simstate.set(iaddr, dstop, result)
                simstate.clear_flag(iaddr, 'OF')
                simstate.clear_flag(iaddr, 'CF')
                simstate.update_flag(iaddr, 'SF', result.is_negative)
                simstate.update_flag(iaddr, 'ZF', result.is_zero)
                simstate.update_flag(iaddr, 'PF', result.is_odd_parity)
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    ("Xor cannot be applied to " + str(dstval)))
