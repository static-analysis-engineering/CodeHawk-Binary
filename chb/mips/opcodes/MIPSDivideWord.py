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
    from chb.simulation.SimulationState import SimulationState


@mipsregistry.register_tag("div", MIPSOpcode)
class MIPSDivideWord(MIPSOpcode):
    """DIV rs, rt

    Divide Word.
    Divide 32-bit integers.

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

    @property
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
    def rs_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[2])

    @property
    def rt_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[3])

    # --------------------------------------------------------------------------
    # Operation:
    #   q <- GPR[rs][31..0] div GPR[rt][31..0]
    #   LO <- q
    #   r <- GPRprs[p31..0] mod GPR[rt][31..0]
    #   HI <- r
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        dsthi = self.dsthi_operand
        dstlo = self.dstlo_operand
        srcrs = self.rs_operand
        srcrt = self.rt_operand
        src1val = simstate.rhs(iaddr, srcrs)
        src2val = simstate.rhs(iaddr, srcrt)

        if src1val.is_undefined or src2val.is_undefined:
            resultlo = SV.simUndefinedDW
            resulthi = SV.simUndefinedDW
            simstate.add_logmsg(
                "warning",
                "some operand of division not defined: "
                + str(src1val) + " / " + str(src2val))

        elif src1val.is_symbol or src2val.is_symbol:
            expr = str(src1val) + " / " + str(src2val)
            raise SU.CHBSymbolicExpression(simstate, iaddr, dstlo, expr)

        elif src1val.is_literal and src2val.is_literal:
            v1 = src1val.literal_value
            v2 = src2val.literal_value
            resultlo = cast(SV.SimDoubleWordValue, SV.mk_simvalue(v1 // v2))
            resulthi = cast(SV.SimDoubleWordValue, SV.mk_simvalue(v1 % v2))

        else:
            resultlo = SV.simUndefinedDW
            resulthi = SV.simUndefinedDW
            simstate.add_logmsg(
                "warning",
                "some operand of division not recognized: "
                + str(src1val) + " / " + str(src2val))

        lhslo = simstate.set(iaddr, dstlo, resultlo)
        lhshi = simstate.set(iaddr, dsthi, resulthi)
        simstate.increment_programcounter()
        return SU.simassign(
            iaddr,
            simstate,
            lhslo,
            resultlo,
            intermediates=str(lhshi) + ' := ' + str(resulthi))
