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


@mipsregistry.register_tag("teq", MIPSOpcode)
class MIPSTrapIfEqual(MIPSOpcode):
    """Trap if equal.

    TEQ rs, rt

    args[0]: code field (bits 15:6)
    args[1]: index of rs in mipsdictionary
    args[2]: index of rt in mipsdictionary
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        return [self.mipsd.mips_operand(i) for i in self.args[1:]]

    def annotation(self, xdata: InstrXData) -> str:
        """data format: a:xxxx

        xprs[0]: rhs1
        xprs[1]: rhs2
        xprs[2]: rhs1 == rhs2 (syntactic)
        xprs[3]: rhs1 == rhs2 (simplified)
        """

        rhs1 = str(xdata.xprs[0])
        rhs2 = str(xdata.xprs[1])
        result = xdata.xprs[3]
        rresult = xdata.xprs[4]
        xresult = simplify_result(xdata.args[3], xdata.args[4], result, rresult)
        return 'trap if ' + rhs1 + ' == ' + rhs2 + ' (' + xresult + ')'

    @property
    def src1_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    @property
    def src2_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   if GPR[rs] = GPR[rt] then
    #     SignalException(Trap)
    #   endif
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "MIPSimulationState") -> str:
        src1op = self.src1_operand
        src2op = self.src2_operand
        src1val = simstate.get_rhs(iaddr, src1op)
        src2val = simstate.get_rhs(iaddr, src2op)
        if src1val.is_symbol or src2val.is_symbol:
            expr = str(src1val) + ' == ' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate, iaddr, src1op, expr)
        elif (src1val.is_literal
              and src1val.is_defined
              and src2val.is_literal
              and src2val.is_defined):
            src1val = cast(SV.SimLiteralValue, src1val)
            src2val = cast(SV.SimLiteralValue, src2val)
            if src1val.value == src2val.value:
                raise SU.CHBSimTrapSignalException(
                    simstate, iaddr, src1val, src2val)
            else:
                simstate.increment_program_counter()
                return 'trap if equal: ' + str(src1val) + ', ' + str(src2val)
        else:
            simstate.increment_program_counter()
            return 'trap if equal: ?'
