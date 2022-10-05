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

from typing import cast, List, Tuple, TYPE_CHECKING

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
    import chb.arm.ARMDictionary


@armregistry.register_tag("CMP", ARMOpcode)
class ARMCompare(ARMOpcode):
    """Subtracts a register or immediate value from a register value and sets flags.

    CMP<c> <Rn>, <Rm>

    tags[1]: <c>
    args[0]: index of rn in armdictionary
    args[1]: index of rm in armdictionary
    args[2]: is-wide (thumb)

    xdata format: a:xxxrr
    ---------------------
    xprs[0]: xrn
    xprs[1]: xrm
    xprs[2]: xrn - xrm (simplified)
    rdefs[0]: rn
    rdefs[1]: rm
    rdefs[2..]: xrn - xrm (simplified)
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "Compare")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[:-1]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[:-1]]

    def annotation(self, xdata: InstrXData) -> str:
        rhs1 = str(xdata.xprs[0])
        rhs2 = str(xdata.xprs[1])
        result = str(xdata.xprs[2])
        return "compare " + str(rhs1) + " and " + str(rhs2) + " (" + result + ")"

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "CMP"]

        rhs = xdata.xprs[2]
        rdefs = xdata.reachingdefs

        (ll_rhs1, _, _) = self.opargs[0].ast_rvalue(astree)
        (ll_rhs2, _, _) = self.opargs[1].ast_rvalue(astree)
        ll_expr = astree.mk_binary_op("minus", ll_rhs1, ll_rhs2)

        ll_assign = astree.mk_assign(
            astree.ignoredlhs,
            ll_expr,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        hl_rhss = XU.xxpr_to_ast_exprs(rhs, xdata, astree)
        if len(hl_rhss) == 1:
            hl_rhs = hl_rhss[0]
            hl_assign = astree.mk_assign(
                astree.ignoredlhs,
                hl_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)

            astree.add_instr_mapping(hl_assign, ll_assign)
            astree.add_instr_address(hl_assign, [iaddr])
            astree.add_expr_mapping(hl_rhs, ll_expr)
            astree.add_expr_reachingdefs(ll_rhs1, [rdefs[0]])
            astree.add_expr_reachingdefs(ll_rhs2, [rdefs[1]])
            astree.add_expr_reachingdefs(hl_rhs, rdefs[2:])

            return ([hl_assign], [ll_assign])

        else:
            raise UF.CHBError(
                "ARMCompare: multiple lval/expressions in ast: "
                + ", ".join(str(x) for x in hl_rhss))
