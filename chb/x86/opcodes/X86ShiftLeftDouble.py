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


@x86registry.register_tag("shld", X86Opcode)
class X86ShiftLeftDouble(X86Opcode):
    """SHLD dst, src, shift

    args[0]: index of dst in x86dictionary
    args[1]: index of src in x86dictionary
    args[2]: index of shift in x86dictionary
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
    def shift_operand(self) -> X86Operand:
        return self.x86d.operand(self.args[2])

    @property
    def operands(self) -> Sequence[X86Operand]:
        return [self.dst_operand, self.src_operand, self.shift_operand]

    def annotation(self, xdata: InstrXData) -> str:
        """data format a:vxxxxx .

        vars[0]: dst
        xprs[0]: dst-rhs
        xprs[1]: dst-rhs (simplified)
        xprs[2]: src
        xprs[3]: src (simplified)
        xprs[4]: shift
        """

        lhs = str(xdata.vars[0])
        dstrhs = str(xdata.xprs[0])
        rdstrhs = str(xdata.xprs[1])
        srcrhs = str(xdata.xprs[2])
        rsrcrhs = str(xdata.xprs[3])
        shift = str(xdata.xprs[4])
        return (
            lhs
            + ' = '
            + rdstrhs
            + ' shift in left '
            + rsrcrhs
            + ' by '
            + shift
            + ' bits')

    # --------------------------------------------------------------------------
    # The instruction shifts the first operand (destination operand) to the left
    # the number of bits specified by the third operand (count operand). The
    # second operand (source operand) provides bits to shift in from the right
    # (starting with bit 0 of the destination operand).
    #
    # The count operand is an unsigned integer. If the count operand is CL, the
    # shift count is the logical AND of CL and a count mask; only bits 0 through 4
    # of the count are used. This masks the count to a value between 0 and 31. If
    # a count is greater than the operand size, the result is undefined.
    #
    # If the count is 1 or greater, the CF flag is filled with the last bit
    # shifted out of the destination operand. For a 1-bit shift, the OF flag is
    # set if a sign change occurred; otherwise, it is cleared. If the count
    # operand is 0, flags are not affected.
    #
    # Flags affected:
    # If the count is 1 or greater, the CF flag is filled with the last bit
    # shifted out of the destination operand and the SF, ZF, and PF flags
    # are set according to the value of the result. For a 1-bit shift, the OF
    # flag is set if a sign change occurred; otherwise, it is cleared. For
    # shifts greater than 1 bit, the OF flag is undefined.
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "X86SimulationState") -> None:
        srcop = self.src_operand
        shiftop = self.shift_operand
        dstop = self.dst_operand
        srcval = simstate.get_rhs(iaddr, srcop)
        shiftval = simstate.get_rhs(iaddr, shiftop)
        dstval = simstate.get_rhs(iaddr, dstop)
        if (
                shiftval.is_literal
                and srcval.is_literal
                and dstval.is_literal
                and dstval.is_doubleword):
            shiftval = cast(SV.SimLiteralValue, shiftval)
            dstval = cast(SV.SimDoubleWordValue, dstval)
            srcval = cast(SV.SimLiteralValue, srcval)
            (cflag, result) = dstval.bitwise_shld(srcval, shiftval)
            simstate.set(iaddr, dstop, result)
            if shiftval.value > 0:
                if shiftval.value == 1:
                    msbd = dstval.msb
                    msbr = result.msb
                    if msbd == msbr:
                        simstate.clear_flag(iaddr, 'OF')
                    else:
                        simstate.set_flag(iaddr, 'OF')
                else:
                    simstate.undefine_flag(iaddr, 'OF')
                simstate.update_flag(iaddr, 'CF', cflag == 1)
                simstate.update_flag(iaddr, 'SF', result.is_negative)
                simstate.update_flag(iaddr, 'ZF', result.is_zero)
                simstate.update_flag(iaddr, 'PF', result.is_odd_parity)
        else:
            SU.CHBSimError(
                simstate,
                iaddr,
                ("ShiftLeftDouble not yet implemented for "
                 + str(dstop)
                 + ":"
                 + str(dstval)
                 + ", "
                 + str(srcop)
                 + ":"
                 + str(srcval)
                 + ", "
                 + str(shiftop)
                 + ":"
                 + str(shiftval)))
