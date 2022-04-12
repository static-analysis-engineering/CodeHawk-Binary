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

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree
from chb.app.ASTNode import ASTExpr, ASTInstruction

from chb.app.InstrXData import InstrXData

from chb.invariants.XVariable import XVariable
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


@mipsregistry.register_tag("movn", MIPSOpcode)
class MIPSMoveConditionalNotZero(MIPSOpcode):
    """MOVN rd, rs, rt

    Move Conditional Not Zero.
    Conditionally move a GPR after testing a GPR value.

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
        xprs[0]: rhs
        xprs[1]: testxpr
        xprs[2]: condition (simplified)
        xprs[3]: rhs of lhs (alternative value)
        """

        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[0])
        cond = xdata.xprs[1]
        ccond = xdata.xprs[2]
        xcond = simplify_result(xdata.args[2], xdata.args[3], cond, ccond)
        return 'if ' + xcond + ' then ' + lhs + ' := ' + rhs

    def ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[ASTInstruction]:
        lhss = XU.xvariable_to_ast_lvals(xdata.vars[0], astree)
        conds = XU.xxpr_to_ast_exprs(xdata.xprs[2], astree)
        rhs2s = XU.xxpr_to_ast_exprs(xdata.xprs[3], astree)
        rhs1s = XU.xxpr_to_ast_exprs(xdata.xprs[0], astree)
        if (
                len(lhss) == 1
                and len(conds) == 1
                and len(rhs2s) == 1
                and len(rhs1s) == 1):
            lhs = lhss[0]
            cond = conds[0]
            rhs2 = rhs2s[0]
            rhs1 = rhs1s[0]
            rhs = astree.mk_question(cond, rhs1, rhs2)
            assign = astree.mk_assign(lhs, rhs)
            astree.add_instruction_span(assign.id, iaddr, bytestring)
            return [assign]
        else:
            raise UF.CHBError(
                "MIPSMoveConditionalNotZero: multiple expressions/lvals in ast")

    @property
    def test_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[2])

    @property
    def src_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    @property
    def dst_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   if GPR[rt] <> 0 then
    #       GPR[rd] <- GPR[rs]
    #   endif
    # ---------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        conop = self.test_operand
        conval = simstate.rhs(iaddr, conop)

        if conval.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "movn: condition value undefined")

        elif conval.is_literal:
            if conval.literal_value != 0:
                dstop = self.dst_operand
                srcop = self.src_operand
                srcval = simstate.rhs(iaddr, srcop)
                lhs = simstate.set(iaddr, dstop, srcval)
                result = SU.simassign(iaddr, simstate, lhs, srcval)
            else:
                result = str(conval) + " == 0: nop"
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "movn: condition value not recognized: " + str(conval))

        simstate.increment_programcounter()
        return result
