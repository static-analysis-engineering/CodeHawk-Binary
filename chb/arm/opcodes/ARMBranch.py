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

from typing import (
    Any, cast, Dict, List, Optional, Sequence, Tuple, TYPE_CHECKING)

from chb.app.InstrXData import InstrXData

from chb.arm.ARMCallOpcode import ARMCallOpcode
from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand
from chb.arm.ARMOperandKind import ARMOperandKind, ARMAbsoluteOp

from chb.ast.AbstractSyntaxTree import nooffset
import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.bctypes.BCTyp import BCTyp

from chb.invariants.XXpr import XXpr, XprCompound
import chb.invariants.XXprUtil as XU

from chb.models.ModelsAccess import ModelsAccess
from chb.models.ModelsType import MNamedType

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget, AppTarget, StaticStubTarget
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.VConstantValueVariable import VFunctionReturnValue


@armregistry.register_tag("B", ARMOpcode)
class ARMBranch(ARMCallOpcode):
    """branch instruction.

    B<c> label
    B<c>.W label

    tags[1]: <c>
    args[0]: index of target operand in armdictionary
    args[1]: is-wide (thumb)

    xdata format: a:xxxxxr..
    ------------------------
    xprs[0]: true condition
    xprs[1]: false condition
    xprs[2]: true condition (simplified)
    xprs[3]: false condition (simplified)
    xprs[4]: target address (absolute)

    or, if no conditions

    xdata format: a:x
    xprs[0]: target address (absolute)
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMCallOpcode.__init__(self, d, ixval)
        self.check_key(2, 2, "Branch")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[1] == 1 else ""
        return cc + wide

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    def ft_conditions_basic(self, xdata: InstrXData) -> Sequence[XXpr]:
        if xdata.has_branch_conditions():
            return [xdata.xprs[1], xdata.xprs[0]]
        else:
            return []

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

    def is_call(self, xdata: InstrXData) -> bool:
        return len(xdata.tags) >= 2 and xdata.tags[1] == "call"

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        return xdata.has_call_target()

    def call_target(self, xdata: InstrXData) -> "CallTarget":
        if self.is_call_instruction(xdata):
            return xdata.call_target(self.ixd)
        else:
            raise UF.CHBError("Instruction is not a call: " + str(self))

    def jump_target(self, xdata: InstrXData) -> Optional["XXpr"]:
        if self.is_call_instruction(xdata):
            return None
        elif xdata.has_branch_conditions():
            return None
        else:
            return xdata.xprs[0]

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        return xdata.xprs

    def annotation(self, xdata: InstrXData) -> str:
        if self.is_call_instruction(xdata):
            tgt = xdata.call_target(self.ixd)
            args = ", ".join(str(x) for x in self.arguments(xdata))
            return "call " + str(tgt) + "(" + args + ")"
        elif xdata.has_branch_conditions():
            return "if " + str(xdata.xprs[2]) + " then goto " + str(xdata.xprs[4])
        elif self.tags[1] in ["a", "unc"]:
            return "goto " + str(xdata.xprs[0])
        else:
            return "if ? goto " + str(xdata.xprs[0])

    def target_expr_ast(
            self,
            astree: ASTInterface,
            xdata: InstrXData) -> AST.ASTExpr:
        calltarget = xdata.call_target(self.ixd)
        tgtname = calltarget.name
        if calltarget.is_app_target:
            apptgt = cast("AppTarget", calltarget)
            return astree.mk_global_variable_expr(
                tgtname, globaladdress=int(str(apptgt.address), 16))
        else:
            return astree.mk_global_variable_expr(tgtname)

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        if self.is_call_instruction(xdata) and xdata.has_call_target():
            return self.ast_call_prov(
                astree, iaddr, bytestring, "Branch (B.W)", xdata)
        else:
            return ARMOpcode.ast_prov(
                self, astree, iaddr, bytestring, xdata)

    def ast_call_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            name: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        return ARMCallOpcode.ast_call_prov(
            self, astree, iaddr, bytestring, "Branch (B)", xdata)

    def ast_condition_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData,
            reverse: bool) -> Tuple[
                Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:

        reachingdefs = xdata.reachingdefs

        def default(condition: XXpr) -> AST.ASTExpr:
            astcond = XU.xxpr_to_ast_def_expr(condition, xdata, iaddr, astree)
            return astcond

        # The basic conditions are the false/true conditions expressed in terms
        # of the registers used in the setter instructions (e.g., CMP); the other
        # conditions are those same conditions, but rewritten with the invariants
        # active at the setter statement.
        #
        # Normally we would want to use the rewritten conditions, as they are
        # generally more expressive, but in some cases we use the original, basic
        # conditions, to take into account a variable introduced that may
        # represent the more complex condition, or that may add an appropriate
        # type.
        #
        # The current hypothesis is that even when using the basic conditions, the
        # rewritten conditions will emerge through the reaching definitions, in
        # case there are no rewritten variables, but this still has to be
        # validated with more instances.

        ftconds_basic = self.ft_conditions(xdata)
        ftconds = self.ft_conditions(xdata)

        ll_astcond = self.ast_cc_expr(astree)

        if len(ftconds_basic) == 2:
            if reverse:
                condition = ftconds_basic[0]
            else:
                condition = ftconds_basic[1]

            csetter = xdata.tags[2]
            hl_astcond = XU.xxpr_to_ast_def_expr(
                condition, xdata, csetter, astree)

            astree.add_expr_mapping(hl_astcond, ll_astcond)
            astree.add_expr_reachingdefs(hl_astcond, xdata.reachingdefs)
            astree.add_flag_expr_reachingdefs(
                ll_astcond, xdata.flag_reachingdefs)
            astree.add_condition_address(ll_astcond, [iaddr])

            return (hl_astcond, ll_astcond)

        elif len(ftconds) == 0:
            chklogger.logger.error(
                "No branch condition found at address %s", iaddr)
            hl_astcond = astree.mk_temp_lval_expression()
            return (hl_astcond, ll_astcond)

        else:
            raise UF.CHBError(
                "ARMBranch: one or more than two conditions at " + iaddr)
