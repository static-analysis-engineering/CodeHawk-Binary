# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2024  Aarno Labs LLC
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

from typing import cast, List, Sequence, Optional, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XXpr, XprCompound
import chb.invariants.XXprUtil as XU

from chb.pwr.PowerDictionaryRecord import pwrregistry
from chb.pwr.PowerOpcode import PowerOpcode
from chb.pwr.PowerOperand import PowerOperand

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.pwr.PowerDictionary import PowerDictionary

@pwrregistry.register_tag("blt", PowerOpcode)
@pwrregistry.register_tag("e_blt", PowerOpcode)
@pwrregistry.register_tag("se_blt", PowerOpcode)
class PWRBranchLessThan(PowerOpcode):
    """Conditional branch if less-than

    tags[1]: pit: instruction type
    args[0]: aa: absolute address if 1
    args[1]: bo: BO value (0..31)
    args[2]: bi: BI value (0..31)
    args[3]: bp: index of branch prediction in pwrdictionary
    args[4]: cr: index of condition register field in pwrdictionary
    args[5]: bd: index of branch destination address in pwrdictionary

    xdata format:
    -------------
    xprs[0]: true condition
    xprs[1]: false condition
    xprs[2]: true condition (simplified)
    xprs[3]: false condition (simplified)
    xprs[4]: target address (absolute)
    """

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOpcode.__init__(self, pwrd, ixval)

    @property
    def operands(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(i) for i in self.args[4:]]

    @property
    def opargs(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(i) for i in self.args[3:]]

    def ft_conditions(self, xdata: InstrXData) -> Sequence[XXpr]:
        if xdata.has_branch_conditions():
            return [xdata.xprs[3], xdata.xprs[2]]
        else:
            return []

    def is_condition_true(self, xdata: InstrXData) -> bool:
        ftconds = self.ft_conditions(xdata)
        if len(ftconds) == 2:
            return ftconds[1].is_true
        return False

    def annotation(self, xdata: InstrXData) -> str:
        if xdata.has_branch_conditions():
            return (
                "if " + str(xdata.xprs[2]) + " then goto " + str(xdata.xprs[4]))
        else:
            return "?"

    def ast_condition_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData,
            reverse: bool) -> Tuple[
                Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:

        annotations: List[str] =  [iaddr, "blt"]

        rdefs = xdata.reachingdefs
        zero = astree.mk_integer_constant(0)

        def default(condition: XXpr) -> AST.ASTExpr:
            astconds = XU.xxpr_to_ast_exprs(condition, xdata, iaddr, astree)

            if len(astconds) == 0:
                chklogger.logger.error(
                    "CBranchLessThan (blt) at address %s: No ast value for "
                    + "condition; returning zero", iaddr)
                return zero

            if len(astconds) > 1:
                chklogger.logger.error(
                    "CBranchLessThan (blt) at address %s: Multiple ast values "
                    + "for condition: %s: %s",
                    iaddr,
                    str(condition),
                    ", ".join(str(c) for c in astconds))
                return zero

            return astconds[0]

        ftconds = self.ft_conditions(xdata)
        if len(ftconds) == 2:
            if reverse:
                condition = ftconds[0]
            else:
                condition = ftconds[1]

            if condition.is_register_comparison:
                condition = cast(XprCompound, condition)
                xoperator = condition.operator
                xoperands = condition.operands
                xop1 = xoperands[0]
                xop2 = xoperands[1]

                csetter = xdata.tags[2]
                astop1s = XU.xxpr_to_ast_def_exprs(xop1, xdata, csetter, astree)
                astop2s = XU.xxpr_to_ast_def_exprs(xop2, xdata, csetter, astree)

                if len(astop1s) == 1 and len(astop2s) == 1:
                    hl_astcond = astree.mk_binary_op(
                        xoperator, astop1s[0], astop2s[0])

                else:
                    chklogger.logger.error(
                        "CBranchLessThan (blt) at address %s: Error in ast "
                        + "condition", iaddr)

            elif condition.is_compound:
                csetter = xdata.tags[2]
                astconditions = XU.xxpr_to_ast_def_exprs(
                    condition, xdata, csetter, astree)
                if len(astconditions) == 1:
                    hl_astcond = astconditions[0]

                else:
                    hl_astcond = default(condition)
            else:
                hl_astcond = default(condition)

            astree.add_expr_mapping(hl_astcond, hl_astcond)
            astree.add_expr_reachingdefs(hl_astcond, xdata.reachingdefs)

            return (hl_astcond, hl_astcond)

        elif len(ftconds) == 0:
            chklogger.logger.error(
                "CBranchLessThan (blt) at address %s: No branch condition "
                + "found; return zero", iaddr)

            return (zero, zero)

        else:
            chklogger.logger.error(
                "CBranchLessThan (blt) at address %s: One or more than two "
                + "conditions; returning zero", iaddr)
            return (zero, zero)
