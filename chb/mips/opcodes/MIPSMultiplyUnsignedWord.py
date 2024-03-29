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

from chb.invariants.XVariable import XVariable
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


@mipsregistry.register_tag("multu", MIPSOpcode)
class MIPSMultiplyUnsignedWord(MIPSOpcode):
    """MULTU rs, rt

    Multiply Unsigned Word.
    Multiply 32-bit unsigned integers.

    args[0]: index of hi in mips dictionary
    args[1]: index of lo in mips dictionary
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
        """data format vvxxxx

        vars[0]: lhs-hi
        vars[1]: lhs-lo
        xprs[0]: rhs1 (rs)
        xprs[1]: rhs2 (rt)
        xprs[3]: rhs1 * rhs2 (syntactic)
        xprs[4]: rhs1 * rhs2 (simplified)
        """

        hi = str(xdata.vars[0])
        lo = str(xdata.vars[1])
        result = xdata.xprs[2]
        rresult = xdata.xprs[3]
        xresult = simplify_result(xdata.args[4], xdata.args[5], result, rresult)
        return '(' + hi + ',' + lo + ') := ' + xresult

    @property
    def dstlo_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    @property
    def dsthi_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    @property
    def src1_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[2])

    @property
    def src2_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[3])

    # --------------------------------------------------------------------------
    # Operation:
    #    prod <- (0 || GPR[rs][31..0]) . (0 || GPR[rt][31..0])
    #    LO <- prod[31..0]
    #    HI <- prod[63..32]
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        dstlo = self.dstlo_operand
        dsthi = self.dsthi_operand
        src1op = self.src1_operand
        src2op = self.src2_operand
        src1val = simstate.rhs(iaddr, src1op)
        src2val = simstate.rhs(iaddr, src2op)
        expr = str(src1val) + " * " + str(src2val)

        if src1val.is_undefined or src2val.is_undefined:
            loval = cast(SV.SimValue, SV.simUndefinedDW)
            hival = cast(SV.SimValue, SV.simUndefinedDW)
            simstate.add_logmsg(
                "warning",
                "multu: some operand is undefined: " + expr)

        elif src1val.is_symbol or src2val.is_symbol:
            raise SU.CHBSymbolicExpression(simstate, iaddr, dstlo, expr)

        elif src1val.is_literal and src2val.is_literal:
            v1 = src1val.literal_value
            v2 = src2val.literal_value
            p = v1 * v2
            loval = SV.mk_simvalue(p % (SU.max32 + 1))
            hival = SV.mk_simvalue(p >> 32)

        else:
            loval = SV.simUndefinedDW
            hival = SV.simUndefinedDW
            simstate.add_logmsg(
                "warning",
                "multu: some operand is not a literal: " + expr)

        lhslo = simstate.set(iaddr, dstlo, loval)
        lhshi = simstate.set(iaddr, dsthi, hival)
        simstate.increment_programcounter()
        return SU.simassign(
            iaddr,
            simstate,
            lhslo,
            loval,
            intermediates=str(lhshi) + ' := ' + str(hival))
