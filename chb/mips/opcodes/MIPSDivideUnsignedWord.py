# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
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

from chb.invariants.XXpr import XXpr

from chb.mips.MIPSDictionaryRecord import mipsregistry
from chb.mips.MIPSOpcode import MIPSOpcode, simplify_result
from chb.mips.MIPSOperand import MIPSOperand

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.mips.simulation.MIPSimulationState import MIPSimulationState


@mipsregistry.register_tag("divu", MIPSOpcode)
class MIPSDivideUnsignedWord(MIPSOpcode):
    """DIVU rs, rt

    Divide Unsigned Word
    Divide a 32-bit unsigned integers.

    args[0]: index of HI in mips dictionary
    args[1]: index of LO in mips dictionary
    args[2]: index of rs in mips dictionary
    args[3]: index of rt in mips dictionary
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    def operands(self) -> Sequence[MIPSOperand]:
        return [self.mipsd.mips_operand(i) for i in self.args]

    def annotation(self, xdata: InstrXData) -> str:
        """data format: a:vvxxxxxx.

        vars[0]: lhslo
        vars[1]: lhshi
        xprs[0]: op1
        xprs[1]: op2
        xprs[2]: op1 div op2 (low, syntactic)
        xprs[3]: op1 div op2 (high, syntactic)
        xprs[4]: op1 div op2 (low, simplified)
        xprs[5]: op1 div op2 (high, syntactic)
        """

        lhslo = str(xdata.vars[0])
        lhshi = str(xdata.vars[1])
        resultlo = xdata.xprs[2]
        rresultlo = xdata.xprs[4]
        resulthi = xdata.xprs[3]
        rresulthi = xdata.xprs[5]
        xresultlo = simplify_result(
            xdata.args[4], xdata.args[6], resultlo, rresultlo)
        xresulthi = simplify_result(
            xdata.args[5], xdata.args[7], resulthi, rresulthi)
        pdiv = lhslo + ' := ' + xresultlo
        pmod = lhshi + ' := ' + xresulthi
        return pdiv + '; ' + pmod

    @property
    def dsthi_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    @property
    def dstlo_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    @property
    def src1_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[2])

    @property
    def src2_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[3])

    # --------------------------------------------------------------------------
    # Operation:
    #   q <- (0 || GPR[rs][31..0]) div (0 || GPR[rt][31..0])
    #   r <- (0 || GPR[rs][31..0]) mod (0 || GPR[rt][31..0])
    #   LO <- sign_extend(q[31..0])
    #   HI <- sign_extend(r[31..0])
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "MIPSimulationState") -> str:
        dsthi = self.dsthi_operand
        dstlo = self.dstlo_operand
        src1op = self.src1_operand
        src2op = self.src2_operand
        src1val = simstate.get_rhs(iaddr, src1op)
        src2val = simstate.get_rhs(iaddr, src2op)
        if (
                src1val.is_defined
                and src2val.is_defined
                and src1val.is_doubleword
                and src1val.is_literal
                and src2val.is_literal):
            src1val = cast(SV.SimDoubleWordValue, src1val)
            src2val = cast(SV.SimDoubleWordValue, src2val)
            q = src1val.divu(src2val)
            r = src1val.modu(src2val)
            lhslo = simstate.set(iaddr, dstlo, q)
            lhshi = simstate.set(iaddr, dsthi, r)
            simstate.increment_program_counter()
            return SU.simassign(
                iaddr,
                simstate,
                lhslo,
                q,
                intermediates=str(lhshi) + ' := ' + str(r))
        else:
            lhslo = simstate.set(iaddr, dstlo, SV.simUndefinedDW)
            lhshi = simstate.set(iaddr, dsthi, SV.simUndefinedDW)
            simstate.increment_program_counter()
            return SU.simassign(iaddr, simstate, lhslo, SV.simUndefinedDW)
