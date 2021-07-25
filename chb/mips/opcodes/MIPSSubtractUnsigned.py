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


@mipsregistry.register_tag("subu", MIPSOpcode)
class MIPSSubtractUnsigned(MIPSOpcode):
    """SUBU rd, rs, rt

    Subtract Unsigned Word.
    Subtrac 32-bit integers.

    args[0]: index of rd in mips dictionary
    args[1]: index of rs in mips dictionary
    args[2]: index of rt in mips dictionary
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
        """data format a:vxxxx

        vars[0]: lhs
        xprs[0]: rhs1 (rs)
        xprs[1]: rhs2 (rt)
        xprs[2]: rhs1 - rhs2 (syntactic)
        xprs[3]: rhs1 - rhs2 (simplified)
        """

        lhs = str(xdata.vars[0])
        result = xdata.xprs[2]
        rresult = xdata.xprs[3]
        xresult = simplify_result(xdata.args[3], xdata.args[4], result, rresult)
        return lhs + ' := ' + xresult

    @property
    def dst_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    @property
    def src1_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    @property
    def src2_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   temp <- GPR[rs] - GPR[rt]
    #   GPR[rd] <- temp
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "MIPSimulationState") -> str:
        dstop = self.dst_operand
        src1op = self.src1_operand
        src2op = self.src2_operand
        src1val = simstate.get_rhs(iaddr, src1op)
        src2val = simstate.get_rhs(iaddr, src2op)
        if src1val.is_symbol or src2val.is_symbol:
            expr = str(src1val) + ' - ' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate, iaddr, dstop, expr)
        if src1val.is_string_address and src2val.is_string_address:
            src1val = cast(SSV.SimStringAddress, src1val)
            src2val = cast(SSV.SimStringAddress, src2val)
            diff = src2val.stringval.find(src1val.stringval)
            result = SV.mk_simvalue(diff)
        elif src1val.is_literal and src1val.is_defined:
            src1val = cast(SV.SimDoubleWordValue, src1val)
            result = src1val.subu(src2val)
        elif src1val.is_stack_address and src2val.is_stack_address:
            src1val = cast(SSV.SimStackAddress, src1val)
            src2val = cast(SSV.SimStackAddress, src2val)
            diff = src1val.offsetvalue - src2val.offsetvalue
            result = SV.mk_simvalue(diff)
        else:
            result = SV.simUndefinedDW
        lhs = simstate.set(iaddr, dstop, result)
        simstate.increment_program_counter()
        return SU.simassign(
            iaddr,
            simstate,
            lhs,
            result,
            ('val('
             + str(src1op)
             + ') = '
             + str(src1val)
             + ', val('
             + str(src2op)
             + ') = '
             + str(src2val)))
