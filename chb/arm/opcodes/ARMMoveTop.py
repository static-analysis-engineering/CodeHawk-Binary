# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("MOVT", ARMOpcode)
class ARMMoveTop(ARMOpcode):
    """Writes an immediate value to the top halfword of the destination register.

    MOVT<c> <Rd>, #<imm16>

    tags[1]: <c>
    args[0]: index of Rd in arm dictionary
    args[1]: index of imm16 in arm dictionary

    xdata format: a:vxxxxxrdh
    -------------------------
    vars[0]: lhs
    xprs[0]: immediate value
    xprs[1]: rhs
    xprs[2]: rhs shifted by 16 bits
    xprs[3]: result
    xprs[4]: result (simplified)
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 2, "MoveTop")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args]

    def annotation(self, xdata: InstrXData) -> str:
        lhs = str(xdata.vars[0])
        result = xdata.xprs[3]
        rresult = xdata.xprs[4]
        xresult = simplify_result(xdata.args[4], xdata.args[5], result, rresult)
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

        annotations: List[str] = [iaddr, "MOVT"]

        # low-level assignment

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs1, _, _) = self.opargs[0].ast_rvalue(astree)
        (ll_rhs2, _, _) = self.opargs[1].ast_rvalue(astree)
        mask = astree.mk_integer_constant(0xffff)
        shift = astree.mk_integer_constant(16)
        ll_x1 = astree.mk_binary_op("band", ll_rhs1, mask)
        ll_x2 = astree.mk_binary_op("lsl", ll_rhs2, shift)
        ll_result = astree.mk_binary_op("plus", ll_x1, ll_x2)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_result,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignment

        lhs = xdata.vars[0]
        rhs = xdata.xprs[4]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)
        hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_reg_definition(iaddr, hl_lhs, hl_rhs)
        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_result)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(ll_result, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_rhs1, [rdefs[0]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        return ([hl_assign], [ll_assign])
