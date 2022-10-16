# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
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

from typing import List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XprCompound
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.arm.ARMDictionary


@armregistry.register_tag("ADC", ARMOpcode)
class ARMAddCarry(ARMOpcode):
    """Adds an immediate/register value and the carry flag to a register value.

    ADC<c> <Rd>, <Rn>, #<const>

    tags[1]: <c>
    args[0]: {S}
    args[1]: index of op1 in armdictionary
    args[2]: index of op2 in armdictionary
    args[3]: index of op3 in armdictionary
    args[4]: is-wide (thumb)

    xdata format: a:vxxxxrrdh
    -------------------------
    vars[0]: lhs (Rd)
    xprs[0]: rhs1 (Rn)
    xprs[1]: rhs2 (Rm)
    xprs[2]: rhs1 + rhs2
    xprs[3]: rhs1 + rhs2 (simplified)
    rdefs[0]: rhs1
    rdefs[1]: rhs2
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "AddCarry")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:-1]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:-1]]

    @property
    def writeback(self) -> bool:
        return self.args[0] == 1

    def mnemonic_extension(self) -> str:
        wb = "S" if self.writeback else ""
        cc = ARMOpcode.mnemonic_extension(self)
        return wb + cc

    def annotation(self, xdata: InstrXData) -> str:
        lhs = str(xdata.vars[0])
        result = xdata.xprs[2]
        rresult = xdata.xprs[3]
        xresult = simplify_result(xdata.args[3], xdata.args[4], result, rresult)
        assignment = lhs + " := " + xresult
        if xdata.has_unknown_instruction_condition():
            return "if ? then " + assignment
        elif xdata.has_instruction_condition():
            c = str(xdata.xprs[1])
            return "if " + c + " then " + assignment
        else:
            return assignment

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "ADC"]

        lhs = xdata.vars[0]
        rhs1 = xdata.xprs[0]
        rhs2 = xdata.xprs[1]
        rhssum = xdata.xprs[2]
        rhs3 = xdata.xprs[3]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        (ll_lhs, _, _) = self.operands[0].ast_lvalue(astree)
        (ll_op1, _, _) = self.operands[1].ast_rvalue(astree)
        (ll_op2, _, _) = self.operands[2].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("plus", ll_op1, ll_op2)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        lhsasts = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        if len(lhsasts) == 0:
            raise UF.CHBError("Adc: no lval found")

        if len(lhsasts) > 1:
            raise UF.CHBError(
                "Adc: multiple lvals in ast: "
                + ", ".join(str(v) for v in lhsasts))

        hl_lhs = lhsasts[0]

        rhsasts = XU.xxpr_to_ast_def_exprs(rhs3, xdata, iaddr, astree)
        if len(rhsasts) == 0:
            raise UF.CHBError("Adc: no rhs value found")

        if len(rhsasts) > 1:
            raise UF.CHBError(
                "Multiple rhs values found for Adc: "
                + ", ".join(str(v) for v in rhsasts))

        hl_rhs = rhsasts[0]

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_reg_definition(iaddr, hl_lhs, hl_rhs)
        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[0], rdefs[1]])
        astree.add_expr_reachingdefs(ll_op1, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_op2, [rdefs[1]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        return ([hl_assign], [ll_assign])
