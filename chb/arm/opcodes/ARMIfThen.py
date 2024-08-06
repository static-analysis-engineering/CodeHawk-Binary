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

from typing import cast, List, Optional, Sequence, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("IT", ARMOpcode)
class ARMIfThen(ARMOpcode):
    """Makes up to four following instructions conditional.

    The conditions for the instructions in the IT block are the same as, or the
    inverse of, the condition of the IT instruction specified for the first
    instruction in the block..

    IT{<x>{<y>{<z>}}} <firstcond>

    tags[1]: <c>
    tags[2]: xyz
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)

    @property
    def operands(self) -> List[ARMOperand]:
        return []

    def ft_conditions(self, xdata: InstrXData) -> Sequence[XXpr]:
        if xdata.has_branch_conditions():
            return [xdata.xprs[3], xdata.xprs[2]]
        else:
            return []

    def annotation(self, xdata: InstrXData) -> str:
        if len(xdata.vars) == 1 and len(xdata.xprs) == 2:
            lhs = str(xdata.vars[0])
            rhs = str(xdata.xprs[1])
            return lhs + " := " + rhs
        elif xdata.has_branch_conditions():
            return "if " + str(xdata.xprs[3]) + " then goto "
        else:
            return self.tags[0]

    def ast_condition_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData,
            reverse: bool) -> Tuple[Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:

        annotations: List[str] = [iaddr, "IT"]

        reachingdefs = xdata.reachingdefs

        ftconds = self.ft_conditions(xdata)
        if len(ftconds) == 2:
            if reverse:
                condition = ftconds[0]
            else:
                condition = ftconds[1]

        hl_astcond = XU.xxpr_to_ast_def_expr(condition, xdata, iaddr, astree)
        ll_astcond = self.ast_cc_expr(astree)

        astree.add_expr_mapping(hl_astcond, ll_astcond)
        astree.add_expr_reachingdefs(hl_astcond, xdata.reachingdefs)
        astree.add_flag_expr_reachingdefs(ll_astcond, xdata.flag_reachingdefs)
        astree.add_condition_address(ll_astcond, [iaddr])

        return (hl_astcond, ll_astcond)

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "IT"]

        if len(xdata.vars) == 0:
            return ([], [])

        lhs = xdata.vars[0]
        rhs = xdata.xprs[1]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        hl_rhss = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)
        if len(hl_lhss) == 1 and len(hl_rhss) == 1:
            hl_lhs = hl_lhss[0]
            hl_rhs = hl_rhss[0]
            hl_assign = astree.mk_assign(
                hl_lhs,
                hl_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)

            subsumes = xdata.subsumes()

            astree.add_reg_definition(iaddr, hl_lhs, hl_rhs)
            astree.add_instr_address(hl_assign, [iaddr] + subsumes)
            astree.add_expr_reachingdefs(hl_rhs, rdefs)
            astree.add_lval_defuses(hl_lhs, defuses[0])
            astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

            return ([hl_assign], [])

        else:
            raise UF.CHBError(
                "ARMIfThen: multiple lval/expressions in ast")
