# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs LLC
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


@armregistry.register_tag("LSR", ARMOpcode)
class ARMLogicalShiftRight(ARMOpcode):
    """Shifts a register value right by an immediate value, or value in a register.

    LSR{S}<c> <Rd>, <Rn>, <Rm>

    tags[1]: <c>
    args[0]: {S}
    args[1]: index of Rd in armdictionary
    args[2]: index of Rn in armdictionary
    args[3]: index of Rm in armdictionary
    args[4]: is-wide (thumb)

    xdata format: a:vxxxxrrdh
    -------------------------
    vars[0]: lhs
    xprs[0]: xrn
    xprs[1]: xrm
    xprs[2]: xrn >> xrm
    xprs[3]: xrn >> xrm (simplified)
    rdefs[0]: xrm
    rdefs[1]: xrn
    rdefs[2..]: xrn >> xrm (simplified)
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[4] == 1 else ""
        return cc + wide

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:-1]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:-1]]

    @property
    def mnemonic(self) -> str:
        mnem = self.tags[0]
        if self.is_writeback:
            return mnem + "S"
        else:
            return mnem

    @property
    def is_writeback(self) -> bool:
        return self.args[0] == 1

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

        annotations: List[str] = [iaddr, "LSR"]

        lhs = xdata.vars[0]
        rhs1 = xdata.xprs[0]
        rhs2 = xdata.xprs[1]
        result = xdata.xprs[3]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_op1, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_op2, _, _) = self.opargs[2].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("lsr", ll_op1, ll_op2)

        astree.add_expr_reachingdefs(ll_op1, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_op2, [rdefs[1]])

        hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        if len(hl_lhss) == 0:
            raise UF.CHBError("LSR): no lhs found")

        if len(hl_lhss) > 1:
            raise UF.CHBError(
                "LSR: Multiple lhs locations found: "
                + ", ".join(str(l) for l in hl_lhss))

        hl_rhss = XU.xxpr_to_ast_def_exprs(result, xdata, iaddr, astree)
        if len(hl_rhss) == 0:
            raise UF.CHBError("LSR: no rhs found")

        if len(hl_rhss) > 1:
            raise UF.CHBError(
                "LSR: Multiple rhs values found: "
                + ", ".join(str(v) for v in hl_rhss))

        hl_lhs = hl_lhss[0]
        hl_rhs = hl_rhss[0]

        return self.ast_variable_intro(
            astree,
            astree.astree.unsigned_int_type,
            hl_lhs,
            hl_rhs,
            ll_lhs,
            ll_rhs,
            rdefs[2:],
            rdefs[:2],
            defuses[0],
            defuseshigh[0],
            True,
            iaddr,
            annotations,
            bytestring)
