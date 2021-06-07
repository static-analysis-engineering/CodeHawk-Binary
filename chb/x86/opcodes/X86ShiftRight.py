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


@x86registry.register_tag("shr", X86Opcode)
class X86ShiftRight(X86Opcode):
    """SHR dst, op

    args[0]: index of dst in x86dictionary
    args[1]: index of src in x86dictionary
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def dst_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[0])

    @property
    def src_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[1])

    @property
    def operands(self) -> Sequence[X86Operand]:
        return [self.dst_operand, self.src_operand]

    def annotation(self, xdata: InstrXData) -> str:
        """data format a:vxxxx

        vars[0]: dst
        xprs[0]: rhs-base
        xprs[1]: rhs-expr
        xprs[2]: rhs-result (syntactic)
        xprs[3]: rhs-result (simplified)
        """

        lhs = str(xdata.vars[0])
        rhs = xdata.xprs[2]
        rrhs = xdata.xprs[3]
        xrhs = simplify_result(xdata.args[3], xdata.args[4], rhs, rrhs)
        return lhs + ' = ' + xrhs

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        return xdata.vars

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    # --------------------------------------------------------------------------
    # Shifts the bits in the first operand (destination operand) to the right by
    # the number of bits specified in the second operand (count operand). Bits
    # shifted beyond the destination operand boundary are first shifted into the
    # CF flag, then discarded. At the end of the shift operation, the CF flag
    # contains the last bit shifted out of the destination operand.
    #
    # The destination operand can be a register or a memory location. The count
    # operand can be an immediate value or the CL register. The count is masked
    # to 5 bits.
    #
    # The instructions shifts the bits of the destination operand to the right
    # (toward less significant bit locations). For each shift count, the least
    # significant bit of the destination operand is shifted into the CF flag,
    # and the most significant bit is cleared.
    #
    # The OF flag is affected only on 1-bit shifts. The OF flag is set to the
    # most-significant bit of the original operand.
    #
    # Flags affected:
    # The CF flag contains the value of the last bit shifted out of the destination
    # operand; it is undefined where the count is greater than or equal to the size
    # (in bits) of the destination operand. The OF flag is affected only for 1-bit
    # shifts; otherwise, it is undefined. The SF, ZF, and PF flags are set according
    # to the result. If the count is 0, the flags are not affected.
    # ---------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        srcop = self.src_operand
        dstop = self.dst_operand
        srcval = simstate.get_rhs(iaddr, srcop)
        dstval = simstate.get_rhs(iaddr, dstop)
        if (
                srcval.is_literal
                and dstval.is_literal
                and dstval.is_doubleword):
            srcval = cast(SV.SimLiteralValue, srcval)
            dstval = cast(SV.SimDoubleWordValue, dstval)
            (cflag, result) = dstval.bitwise_shr(srcval)
            simstate.set(iaddr, dstop, result)
            if srcval.value > 0:
                simstate.update_flag(iaddr, 'CF', cflag == 1)
                if srcval.value == 1:
                    msb = dstval.msb
                    simstate.update_flag(iaddr, 'OF', msb == 1)
                else:
                    simstate.undefine_flag(iaddr, 'OF')
                simstate.update_flag(iaddr, 'CF', cflag == 1)
                simstate.update_flag(iaddr, 'SF', result.is_negative)
                simstate.update_flag(iaddr, 'ZF', result.is_zero)
                simstate.update_flag(iaddr, 'PF', result.is_odd_parity)
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ("ShiftRight not yet supported for "
                 + str(dstop)
                 + ":"
                 + str(dstval)
                 + ", "
                 + str(srcop)
                 + ":"
                 + str(srcval)))
