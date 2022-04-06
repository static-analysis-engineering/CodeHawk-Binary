# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021-2022 Aarno Labs LLC
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
    from chb.simulation.SimulationState import SimulationState


@mipsregistry.register_tag("bgtzl", MIPSOpcode)
class MIPSBranchGTZeroLikely(MIPSBranchOpcode):
    """BGTZL rs, offset

    Branch on Greater Than Zero Likely.
    Test a GPR then do a PC-relative conditional branch; execute the delay
    slot only if the branch is taken.

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

    def ft_conditions(self, xdata: InstrXData) -> Sequence[XXpr]:
        return [xdata.xprs[3], xdata.xprs[2]]

    def annotation(self, xdata: InstrXData) -> str:
        """data format a:xxxx

        xprs[0]: rhs
        xprs[1]: condition (syntactic)
        xprs[2]: condition (simplified)
        xprs[3]: condition (negated)
        """

        result = xdata.xprs[1]
        rresult = xdata.xprs[2]
        xresult = simplify_result(xdata.args[1], xdata.args[2], result, rresult)
        return "if " + xresult + " then goto " + str(self.target)

    @property
    def src_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   I:   target_offset <- sign_extend(offset || 0[2])
    #          condition <- (GPR[rs] > 0[32]
    #   I+1: if condition then
    #          PC <- PC + target_offset
    #        else
    #          NullifyCurrentInstruction
    #        endif
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        srcop = self.src_operand
        srcval = simstate.rhs(iaddr, srcop)
        truetgt = simstate.resolve_literal_address(
            iaddr, self.target.absolute_address_value)
        falsetgt = simstate.programcounter.add_offset(8)
        simstate.increment_programcounter()

        if truetgt.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "bgtzl: branch target address cannot be resolved: "
                + str(self.target.absolute_address_value))

        elif srcval.is_undefined:
            result = SV.simUndefinedBool

        elif srcval.is_literal:
            v = SV.mk_simvalue(srcval.literal_value)
            if v.to_signed_int() > 0:
                result = SV.simtrue
            else:
                result = SV.simfalse

        elif srcval.is_address:
            result = SV.simtrue

        elif srcval.is_file_pointer:
            result = SV.simtrue

        elif srcval.is_symbol:
            srcval = cast(SSV.SimSymbol, srcval)
            result = srcval.is_non_negative

        else:
            result = SV.simUndefinedBool

        if result.is_defined:
            if result.is_true:
                simstate.simprogramcounter.set_delayed_programcounter(truetgt)
            else:
                # delay slot is not executed if condtiion is false
                simstate.simprogramcounter.set_programcounter(falsetgt)
            expr = str(srcval) + " > 0"
            return SU.simbranch(iaddr, simstate, truetgt, falsetgt, expr, result)
        else:
            raise SU.CHBSimBranchUnknownError(
                simstate,
                iaddr,
                truetgt,
                falsetgt,
                "bgtzl: " + str(srcval) + " > 0")
