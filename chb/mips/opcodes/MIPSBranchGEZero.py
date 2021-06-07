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
from chb.mips.opcodes.MIPSBranchOpcode import MIPSBranchOpcode

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.mips.simulation.MIPSimulationState import MIPSimulationState


@mipsregistry.register_tag("bgez", MIPSOpcode)
class MIPSBranchGEZero(MIPSBranchOpcode):
    """BGEZ rs, offset

    Branch on Greater Than or Equal to Zero.

    args[0]: index of rs in mips dictionary
    args[1]: index of offset in mips dictionary
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSBranchOpcode.__init__(self, mipsd, ixval)

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        return [self.mipsd.mips_operand(i) for i in self.args]

    @property
    def target(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    def has_branch_condition(self) -> bool:
        return True

    def branch_condition(self, xdata: InstrXData) -> XXpr:
        return xdata.xprs[2]

    def ft_conditions(self, xdata: InstrXData) -> List[XXpr]:
        return [xdata.xprs[2], xdata.xprs[1]]

    def annotation(self, xdata: InstrXData) -> str:
        """data format a:xxxx

        xprs[0]: rs
        xprs[1]: result
        xprs[2]: result (simplified)
        xprs[3]: result (negated)
        """

        result = xdata.xprs[1]
        rresult = xdata.xprs[2]
        xresult = simplify_result(xdata.args[1], xdata.args[2], result, rresult)
        return 'if ' + xresult + ' then goto ' + str(self.target)

    @property
    def src_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    @property
    def tgt_offset(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   I:    target_offset <- sign_extend(offset || 0[2])
    #         condition <- GPR[rs] >= 0[GPRLEN]
    #   I+1:  if condition then
    #            PC <- PC + target_offset
    #         endif
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "MIPSimulationState") -> str:
        srcop = self.src_operand
        tgtop = self.tgt_offset
        srcval = simstate.get_rhs(iaddr, srcop)
        truetgt = SSV.mk_global_address(tgtop.absolute_address_value)
        falsetgt = simstate.programcounter.add_offset(8)
        if srcval.is_literal and srcval.is_defined:
            srcval = cast(SV.SimDoubleWordValue, srcval)
            if srcval.is_non_negative:
                simstate.increment_program_counter()
                result = SV.simtrue
                simstate.set_delayed_program_counter(truetgt)
            else:
                result = SV.simfalse
                simstate.set_delayed_program_counter(falsetgt)
            expr = str(srcval) + ' >= 0'
            return SU.simbranch(iaddr, simstate, truetgt, falsetgt, expr, result)

        elif srcval.is_symbol:
            srcval = cast(SSV.SimSymbol, srcval)
            simstate.increment_program_counter()
            result = srcval.is_non_negative
            if result.is_defined:
                if result.is_true:
                    simstate.set_delayed_program_counter(truetgt)
                else:
                    simstate.set_delayed_program_counter(falsetgt)
                expr = str(srcval) + ' >= 0'
                return SU.simbranch(iaddr, simstate, truetgt, falsetgt, expr, result)

        raise SU.CHBSimBranchUnknownError(
            simstate,
            iaddr,
            truetgt,
            falsetgt,
            ('branch greater or equal to zero condition: '
             + str(srcval)
             + ' >= 0'))
