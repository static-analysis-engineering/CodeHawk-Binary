# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021-2023 Aarno Labs LLC
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

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XXpr

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


@mipsregistry.register_tag("sltu", MIPSOpcode)
class MIPSSetLTUnsigned(MIPSOpcode):
    """SLTU rd, rs, rt

    Set on Less Than Unsigned
    Record the result of an unsigned less-than comparison

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
        xprs[2]: rhs1 < rhs2 (syntactic)
        xprs[3]: rhs1 < rhs2 (simplified)
        """

        lhs = str(xdata.vars[0])
        result = xdata.xprs[2]
        rresult = xdata.xprs[3]
        xresult = simplify_result(xdata.args[2], xdata.args[3], result, rresult)
        return lhs + ' := 1 if ' + xresult + ' else 0'

    def ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        lhss = XU.xvariable_to_ast_lvals(xdata.vars[0], xdata, astree)
        rhss = XU.xxpr_to_ast_exprs(xdata.xprs[3], xdata, iaddr, astree)
        if len(lhss) == 1 and len(rhss) == 1:
            lhs = lhss[0]
            rhs = rhss[0]
            assign = astree.mk_assign(lhs, rhs)
            astree.add_instruction_span(assign.locationid, iaddr, bytestring)
            return [assign]
        else:
            raise UF.CHBError(
                "MIPSSetLTUnsigned: multiple expressions/lvals in ast")

    @property
    def src1_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    @property
    def src2_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[2])

    @property
    def dst_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   if (0 || GPR[rs]) < (0 || GPR[rt]) then
    #     GPR[rd] <- 0[GPRLEN-1] || 1
    #   else
    #     GPR[rd] <- 0[GPRLEN]
    #   endif
    # ---------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        dstop = self.dst_operand
        src1op = self.src1_operand
        src2op = self.src2_operand
        src1val = simstate.rhs(iaddr, src1op)
        src2val = simstate.rhs(iaddr, src2op)
        expr = str(src1val) + " < " + str(src2val)

        if src1val.is_undefined or src2val.is_undefined:
            result = cast(SV.SimValue, SV.simUndefinedDW)
            simstate.add_logmsg(
                "warning",
                "sltu: operand is not defined: " + expr)

        elif src1val.is_literal and src2val.is_literal:
            if src1val.literal_value < src2val.literal_value:
                result = SV.simOne
            else:
                result = SV.simZero

        elif src1val.is_address and src2val.is_address:
            src1addr = cast(SSV.SimAddress, src1val)
            src2addr = cast(SSV.SimAddress, src2val)
            if src1addr.base == src2addr.base:
                if src1addr.offsetvalue < src2addr.offsetvalue:
                    result = SV.simOne
                else:
                    result = SV.simZero
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "Illegal address comparison with different bases: "
                    + src1addr.base
                    + " and "
                    + src2addr.base)

        elif src1val.is_symbol or src2val.is_symbol:
            raise SU.CHBSymbolicExpression(simstate, iaddr, dstop, expr)

        else:
            result = SV.simUndefinedDW
            simstate.add_logmsg(
                "warning",
                "sltu: some operand not recognized: " + expr)

        lhs = simstate.set(iaddr, dstop, result)
        simstate.increment_programcounter()
        return SU.simassign(iaddr, simstate, lhs, result, expr)
