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

from typing import List, Optional, Sequence, Tuple, TYPE_CHECKING

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
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("CBZ", ARMOpcode)
class ARMCompareBranchZero(ARMOpcode):
    """Compares the value in a register with zero and conditionally branches forward.

    CBZ <Rn>, <label>

    args[0]: index of Rn in arm dictionary
    args[1]: index of label in arm dictionary

    xdata format: a:xxxxxxr..
    -------------------------
    xprs[0]: xrn
    xprs[1]: true condition
    xprs[2]: false condition
    xprs[3]: true condition (simplified)
    xprs[4]: false condition (simplified)
    xprs[5]: target
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(1, 2, "CompareBranchZero")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args]

    def ft_conditions(self, xdata: InstrXData) -> Sequence[XXpr]:
        if xdata.has_branch_conditions():
            return [xdata.xprs[4], xdata.xprs[3]]
        else:
            return []

    def annotation(self, xdata: InstrXData) -> str:
        xpr = str(xdata.xprs[3])
        tgt = str(xdata.xprs[5])
        return "if " + xpr + " goto " + tgt

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        instrs = ARMOpcode.assembly_ast(
            self, astree, iaddr, bytestring, xdata)
        return (instrs, instrs)

    def ast_condition_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData,
            reverse: bool) -> Tuple[
                Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:

        annotations: List[str] = [iaddr, "CBZ"]

        rdefs = xdata.reachingdefs

        (ll_op, _, _) = self.opargs[0].ast_rvalue(astree)
        zero = astree.mk_integer_constant(0)
        if reverse:
            ll_cond = astree.mk_binary_op("ne", ll_op, zero)
        else:
            ll_cond = astree.mk_binary_op("eq", ll_op, zero)

        ftconds = self.ft_conditions(xdata)
        if len(ftconds) == 2:
            if reverse:
                condition = ftconds[0]
            else:
                condition = ftconds[1]

            astconds = XU.xxpr_to_ast_def_exprs(condition, xdata, iaddr, astree)
            if len(astconds) == 0:
                chklogger.logger.error(
                    "CompareBranchZero (CBZ) at address %s: no rhs values "
                    + "found; returning zero", iaddr)
                return (zero, zero)

            if len(astconds) > 1:
                chklogger.logger.error(
                    "CompareBranchZero (CBZ) at address %s: multiple rhs "
                    + "values found at address %s: %s; returning zero",
                    iaddr,
                    ", ".join(str(v) for v in astconds))
                return (zero, zero)

            hl_cond = astconds[0]

            astree.add_expr_mapping(hl_cond, ll_cond)
            astree.add_expr_reachingdefs(hl_cond, rdefs)
            astree.add_expr_reachingdefs(ll_op, [rdefs[0]])
            astree.add_condition_address(ll_cond, [iaddr])

            return (hl_cond, ll_cond)

        else:
            chklogger.logger.error(
                "CompareBranchZero (CBZ) at address %s: no condition "
                + "expressions found; returning zero", iaddr)
            return (zero, zero)
