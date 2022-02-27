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


from typing import cast, List, Optional, Sequence, Tuple, TYPE_CHECKING

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree
from chb.app.ASTNode import ASTExpr, ASTInstruction

from chb.app.InstrXData import InstrXData

from chb.invariants.XXpr import XprConstant
import chb.invariants.XXprUtil as XU

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


@mipsregistry.register_tag("addiu", MIPSOpcode)
class MIPSAddImmediateUnsigned(MIPSOpcode):
    """ADDIU rt, rs, immediate

    Programming notes:
    The term 'unsigned' in the instruction name is a misnomer; this operation
    is 32-bit modulo arithmetic that does not trap an overflow. This instruction
    is appropriate for unsigned arithmetic, such as address arithmetic, or
    integer arithmetic environments that ignore overflow, such as C language
    arithmetic.

    args[0]: index of rt in mips dictionary
    args[1]: index of rs in mips dictionary
    args[2]: index of immediate in mips dictionary
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        return [self.mipsd.mips_operand(i) for i in self.args]

    def strings(self, xdata: InstrXData) -> Sequence[str]:
        result = xdata.xprs[3]
        if result.is_constant:
            c = cast(XprConstant, result)
            cc = result.constant
            if cc.is_string_reference:
                s = cc.string_reference()
                return [s]
        return []

    def string_pointer_loaded(self, xdata: InstrXData) -> Optional[Tuple[str, str]]:
        if len(self.strings(xdata)) == 1:
            return (self.strings(xdata)[0], str(self.dst_operand))
        else:
            return None

    def annotation(self, xdata: InstrXData) -> str:
        """data format a:vxxxx

        vars[0]: lhs
        xprs[0]: rs value
        xprs[1]: imm value
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
        lhs = XU.xvariable_to_ast_lval(xdata.vars[0], astree)
        rhs = XU.xxpr_to_ast_expr(xdata.xprs[3], astree)
        assign = astree.mk_assign(lhs, rhs)
        astree.add_instruction_span(assign.id, iaddr, bytestring)
        return [assign]

    @property
    def dst_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    @property
    def src_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    @property
    def imm_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[2])

    # --------------------------------------------------------------------------
    # Operation:
    #   temp <- GPR[rs] + sign_extend(immediate)
    #   GPR[rt] <- temp
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        dstop = self.dst_operand
        srcop = self.src_operand
        srcval = simstate.rhs(iaddr, srcop)
        immval = self.imm_operand.to_signed_int()
        imm = SV.mk_simvalue(immval)

        def do_assign(result: SV.SimValue) -> str:
            lhs = simstate.set(iaddr, dstop, result)
            simstate.increment_programcounter()
            return SU.simassign(
                iaddr,
                simstate,
                lhs,
                result,
                "val(" + str(srcop) + ") = " + str(srcval))

        if srcval.is_undefined:
            return do_assign(SV.simUndefinedDW)

        if srcval.is_symbol:
            expr = str(srcval) + ' + ' + str(immval)
            raise SU.CHBSymbolicExpression(simstate, iaddr, dstop, expr)

        elif srcval.is_address:
            srcval = cast(SSV.SimAddress, srcval)
            return do_assign(srcval.add_offset(immval))

        elif srcval.is_literal:
            return do_assign(SV.mk_simvalue(srcval.literal_value + immval))

        else:
            return do_assign(SV.simUndefinedDW)
