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


from typing import cast, List, Optional, Sequence, TYPE_CHECKING

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree
from chb.app.ASTNode import ASTExpr, ASTInstruction

from chb.app.InstrXData import InstrXData

from chb.mips.MIPSDictionaryRecord import mipsregistry
from chb.mips.MIPSOpcode import MIPSOpcode, simplify_result
from chb.mips.MIPSOperand import MIPSOperand

import chb.invariants.XXprUtil as XU

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.simulation.SimulationState import SimulationState


@mipsregistry.register_tag("addu", MIPSOpcode)
class MIPSAddUnsigned(MIPSOpcode):
    """ADDU rd, rs, rt

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
        xprs[0]: rs value
        xprs[1]: rt value
        xprs[2]: result (syntactic)
        xprs[3]: result (simplified)
        """

        lhs = str(xdata.vars[0])
        result = xdata.xprs[2]
        rresult = xdata.xprs[3]
        xresult = simplify_result(xdata.args[3], xdata.args[4], result, rresult)
        return lhs + ' := ' + xresult

    def ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[ASTInstruction]:
        lhss = XU.xvariable_to_ast_lvals(xdata.vars[0], astree)
        rhss = XU.xxpr_to_ast_exprs(xdata.xprs[3], astree)
        if len(lhss) == 1 and len(rhss) == 1:
            lhs = lhss[0]
            rhs = rhss[0]
            assign = astree.mk_assign(lhs, rhs)
            astree.add_instruction_span(assign.id, iaddr, bytestring)
            return [assign]
        else:
            raise UF.CHBError(
                "MIPSAddUnsigned: multiple expressions/lvals in ast")

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
    #   temp <- GPR[rs] + GPR[rt]
    #   GPR[rd] <- temp
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        dstop = self.dst_operand
        src1op = self.src1_operand
        src2op = self.src2_operand
        src1val = simstate.rhs(iaddr, src1op)
        src2val = simstate.rhs(iaddr, src2op)

        def do_assign(result: SV.SimValue) -> str:
            lhs = simstate.set(iaddr, dstop, result)
            simstate.increment_programcounter()
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

        if src1val.is_undefined or src2val.is_undefined:
            return do_assign(SV.simUndefinedDW)

        elif src1val.is_symbol or src2val.is_symbol:
            expr = str(src1val) + ' + ' + str(src2val)
            raise SU.CHBSymbolicExpression(simstate, iaddr, dstop, expr)

        # two global addresses, one of which is spurious
        elif (src1val.is_address
              and src2val.is_address
              and src1val.is_literal
              and src2val.is_literal):
            if src1val.literal_value > src2val.literal_value:
                src1addr = cast(SSV.SimAddress, src1val)
                result = cast(
                    SV.SimValue, src1addr.add_offset(src2val.literal_value))
            else:
                src2addr = cast(SSV.SimAddress, src2val)
                result = src2addr.add_offset(src1val.literal_value)
            return do_assign(result)

        elif src2val.is_address and src1val.is_literal:
            src2addr = cast(SSV.SimAddress, src2val)
            result = src2addr.add_offset(src1val.literal_value)
            return do_assign(result)

        elif src1val.is_address and src2val.is_literal:
            src1addr = cast(SSV.SimAddress, src1val)
            result = src1addr.add_offset(src2val.literal_value)
            return do_assign(result)

        elif src1val.is_literal and src2val.is_literal:
            v1 = src1val.literal_value
            v2 = src2val.literal_value
            result = cast(SV.SimValue, SV.mk_simvalue(v1 + v2))
            return do_assign(result)

        else:
            return do_assign(SV.simUndefinedDW)
