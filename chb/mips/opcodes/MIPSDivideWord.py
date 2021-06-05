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
    def simulate(self, iaddr: str, simstate: "MIPSimulationState") -> str:
        dsthi = self.dsthi_operand
        dstlo = self.dstlo_operand
        srcrs = self.rs_operand
        srcrt = self.rt_operand
        src1val = simstate.get_rhs(iaddr, srcrs)
        src2val = simstate.get_rhs(iaddr, srcrt)
        if src1val.is_symbol or src2val.is_symbol:
            expr = str(src1val) + ' / ' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate, iaddr, dstlo, expr)

        elif (src1val.is_literal
              and src1val.is_defined
              and src2val.is_literal
              and src2val.is_defined):
            src1val = cast(SV.SimLiteralValue, src1val)
            src2val = cast(SV.SimLiteralValue, src2val)
            q = src1val.value // src2val.value
            r = src1val.value % src2val.value
            loval = SV.mk_simvalue(q)
            hival = SV.mk_simvalue(r)
        else:
            loval = SV.simUndefinedDW
            hival = SV.simUndefinedDW
        lhslo = simstate.set(iaddr, dstlo, loval)
        lhshi = simstate.set(iaddr, dsthi, hival)
        simstate.increment_program_counter()
        return SU.simassign(
            iaddr,
            simstate,
            lhslo,
            loval,
            intermediates=str(lhshi) + ' := ' + str(hival))
