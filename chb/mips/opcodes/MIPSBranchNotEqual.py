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


@mipsregistry.register_tag("bne", MIPSOpcode)
class MIPSBranchNotEqual(MIPSOpcode):
    """BNE rs, rt, offset

    Branch on Not Equal.
    Compare GPRs then do a PC-relative conditional branch.

    args[0]: index of rs in mips dictionary
    args[1]: index of rt in mips dictionary
    args[2]: index of offset in mips dictionary
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        return [self.mipsd.mips_operand(i) for i in self.args]

    @property
    def target(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[2])

    def has_branch_condition(self) -> bool:
        return True

    def branch_condition(self, xdata: InstrXData) -> XXpr:
        return xdata.xprs[3]

    def annotation(self, xdata: InstrXData) -> str:
        """data format a:xxxxx

        xprs[0]: rhs1
        xprs[1]: rhs2
        xprs[2]: condition (syntactic)
        xprs[3]: condition (simplified)
        xprs[4]: condition (negated)
        """

        result = xdata.xprs[2]
        rresult = xdata.xprs[3]
        xresult = simplify_result(xdata.args[2], xdata.args[3], result, rresult)
        return 'if ' + xresult + ' then goto ' + str(self.target)

    def ft_conditions(self, xdata: InstrXData) -> Sequence[XXpr]:
        return [xdata.xprs[4], xdata.xprs[3]]

    @property
    def src1_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    @property
    def src2_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   I:   target_offset <- sign_extend(offset) || 0[2]
    #        condition <- (GPR[rs] != GPR[rt])
    #   I+1: if condition then
    #          PC <- PC + target_offset
    #        endif
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        src1op = self.src1_operand
        src2op = self.src2_operand
        src1val = simstate.rhs(iaddr, src1op)
        src2val = simstate.rhs(iaddr, src2op)
        tgt = self.target
        truetgt = simstate.resolve_literal_address(iaddr, tgt.absolute_address_value)
        falsetgt = simstate.programcounter.add_offset(8)
        simstate.increment_programcounter()

        if truetgt.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "bne: branch target address cannot be resolved: " + str(tgt))

        if src1val.is_undefined or src2val.is_undefined:
            result = SV.simUndefinedBool

        elif src1val.is_literal and src2val.is_literal:
            if src1val.literal_value == src2val.literal_value:
                result = SV.simfalse
            else:
                result = SV.simtrue

        elif src1val.is_address and src2val.is_address:
            src1val = cast(SSV.SimAddress, src1val)
            src2val = cast(SSV.SimAddress, src2val)
            if src1val.base == src2val.base:
                if src1val.offsetvalue == src2val.offsetvalue:
                    result = SV.simfalse
                else:
                    result = SV.simtrue
            else:
                result = SV.simtrue

        elif src1val.is_address and src2val.is_literal:
            if src2val.literal_value == 0:
                result = SV.simtrue
            else:
                result = SV.simUndefinedBool

        elif src1val.is_file_pointer and src2val.is_literal:
            if src2val.literal_value == 0:
                result = SV.simtrue
            else:
                result = SV.simUndefinedBool

        elif src1val.is_string_address and src2val.is_literal:
            if src2val.literal_value == 0:
                result = SV.simtrue
            else:
                result = SV.simUndefinedBool

        elif src1val.is_string_address and src2val.is_string_address:
            v1 = cast(SSV.SimStringAddress, src1val)
            v2 = cast(SSV.SimStringAddress, src2val)
            if v1.stringval == v2.stringval:
                result = SV.simfalse
            else:
                result = SV.simtrue

        else:
            result = SV.simUndefinedBool

        if result.is_defined:
            if result.is_true:
                simstate.simprogramcounter.set_delayed_programcounter(truetgt)
            else:
                simstate.simprogramcounter.set_delayed_programcounter(falsetgt)
            expr = str(src1val) + ' != ' + str(src2val)
            return SU.simbranch(iaddr, simstate, truetgt, falsetgt, expr, result)
        else:
            raise SU.CHBSimBranchUnknownError(
                simstate,
                iaddr,
                truetgt,
                falsetgt,
                'bne: ' + str(src1val) + ' != ' + str(src2val))
