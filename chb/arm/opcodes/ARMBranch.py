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

from typing import (
    Any, cast, Dict, List, Optional, Sequence, Tuple, TYPE_CHECKING)

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand
from chb.arm.ARMOperandKind import ARMOperandKind, ARMAbsoluteOp

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.bctypes.BCTyp import BCTyp

from chb.invariants.XXpr import XXpr, XprCompound
import chb.invariants.XXprUtil as XU

from chb.models.ModelsAccess import ModelsAccess
from chb.models.ModelsType import MNamedType

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget, AppTarget
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("B", ARMOpcode)
class ARMBranch(ARMOpcode):
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
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 2, "Branch")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    def ft_conditions(self, xdata: InstrXData) -> Sequence[XXpr]:
        if xdata.has_branch_conditions():
            return [xdata.xprs[3], xdata.xprs[2]]
        else:
            return []

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        return xdata.has_call_target()

    def call_target(self, xdata: InstrXData) -> "CallTarget":
        if self.is_call_instruction(xdata):
            return xdata.call_target(self.ixd)
        else:
            raise UF.CHBError("Instruction is not a call: " + str(self))

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

    def lhs_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[AST.ASTLval, List[AST.ASTInstruction]]:

        def indirect_lhs(
                rtype: Optional[AST.ASTTyp]) -> Tuple[
                    AST.ASTLval, List[AST.ASTInstruction]]:
            tmplval = astree.mk_returnval_variable_lval(iaddr, rtype)
            tmprhs = astree.mk_lval_expr(tmplval)
            reglval = astree.mk_register_variable_lval("R0")
            assign = astree.mk_assign(
                reglval, tmprhs, iaddr=iaddr, bytestring=bytestring)
            return (tmplval, [assign])

        calltarget = xdata.call_target(self.ixd)
        tgtname = calltarget.name
        models = ModelsAccess()
        if astree.has_symbol(tgtname):
            fnsymbol = astree.get_symbol(tgtname)
            return indirect_lhs(fnsymbol.vtype)
        else:
            return indirect_lhs(None)

    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        if self.is_call_instruction(xdata) and xdata.has_call_target():
            lhs = astree.mk_register_variable_lval("R0")
            tgt = self.operands[0]
            if tgt.is_absolute:
                tgtaddr = cast(ARMAbsoluteOp, tgt.opkind)
                if self.app.has_function_name(tgtaddr.address.get_hex()):
                    faddr = tgtaddr.address.get_hex()
                    fnsymbol = self.app.function_name(faddr)
                    tgtxpr: AST.ASTExpr = astree.mk_global_variable_expr(
                        fnsymbol, globaladdress=tgtaddr.address.get_int())
                else:
                    (tgtxpr, _, _) = self.operands[0].ast_rvalue(astree)
            else:
                (tgtxpr, _, _) = self.operands[0].ast_rvalue(astree)
            call = astree.mk_call(
                lhs, tgtxpr, [], iaddr=iaddr, bytestring=bytestring)
            return [call]
        else:
            return []

    def ast(self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        if self.is_call_instruction(xdata) and xdata.has_call_target():
            tgtxpr = self.target_expr_ast(astree, xdata)
            (lhs, assigns) = self.lhs_ast(astree, iaddr, bytestring, xdata)
            args = self.arguments(xdata)
            argregs = ["R0", "R1", "R2", "R3"]
            callargs = argregs[:len(args)]
            argxprs: List[AST.ASTExpr] = []
            for (reg, arg) in zip(callargs, args):
                if XU.is_struct_field_address(arg, astree):
                    addr = XU.xxpr_to_struct_field_address_expr(arg, astree)
                    argxprs.append(addr)
                elif arg.is_string_reference:
                    regast = astree.mk_register_variable_expr(reg)
                    cstr = arg.constant.string_reference()
                    saddr = hex(arg.constant.value)
                    argxprs.append(astree.mk_string_constant(regast, cstr, saddr))
                elif arg.is_argument_value:
                    argindex = arg.argument_index()
                    funargs = astree.function_argument(argindex)
                    if len(funargs) != 1:
                        raise UF.CHBError(
                            "ARMBranch: no or multiple function arguments")
                    funarg = funargs[0]
                    if funarg:
                        argxprs.append(astree.mk_lval_expr(funarg))
                    else:
                        argxprs.append(astree.mk_register_variable_expr(reg))
                else:
                    argxprs.append(astree.mk_register_variable_expr(reg))
            if len(args) > 4:
                for a in args[4:]:
                    argxprs.extend(XU.xxpr_to_ast_exprs(a, xdata, astree))
            call = cast(AST.ASTInstruction, astree.mk_call(
                lhs, tgtxpr, argxprs, iaddr=iaddr, bytestring=bytestring))
            return [call] + assigns
        else:
            return []

    def ast_condition_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData,
            reverse: bool) -> Tuple[Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:

        annotations: List[str] = [iaddr, "B"]

        reachingdefs = xdata.reachingdefs

        def default(condition: XXpr) -> AST.ASTExpr:
            astconds = XU.xxpr_to_ast_exprs(condition, xdata, astree)
            if len(astconds) == 0:
                raise UF.CHBError(
                    "Branch (B): no ast value for condition at "
                    + iaddr
                    + " for "
                    + str(condition))

            if len(astconds) > 1:
                raise UF.CHBError(
                    "Branch (B): multiple ast values for condition at "
                    + iaddr
                    + ": "
                    + ", ".join(str(c) for c in astconds)
                    + " for condition "
                    + str(condition))

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
                    hl_astcond = astree.mk_binary_op(xoperator, astop1s[0], astop2s[0])

                else:
                    raise UF.CHBError(
                        "Branch at " + iaddr + ": Error in ast condition")

            elif condition.is_compound:
                condition = cast(XprCompound, condition)
                xoperator = condition.operator
                xoperands = condition.operands
                xop1 = xoperands[0]
                xop2 = xoperands[1]

                if xop1.is_register_variable:
                    csetter = xdata.tags[2]
                    astop1s = XU.xxpr_to_ast_def_exprs(xop1, xdata, csetter, astree)
                    astop2s = XU.xxpr_to_ast_exprs(xop2, xdata, astree)

                    if len(astop1s) == 1 and len(astop2s) == 1:
                        hl_astcond = astree.mk_binary_op(
                            xoperator, astop1s[0], astop2s[0])
                    else:
                        hl_astcond = default(condition)
                else:
                    hl_astcond = default(condition)
            else:
                hl_astcond = default(condition)

            ll_astcond = self.ast_cc_expr(astree)

            astree.add_expr_mapping(hl_astcond, ll_astcond)
            astree.add_expr_reachingdefs(hl_astcond, xdata.reachingdefs)
            astree.add_flag_expr_reachingdefs(ll_astcond, xdata.flag_reachingdefs)
            astree.add_condition_address(ll_astcond, [iaddr])

            return (hl_astcond, ll_astcond)

        elif len(ftconds) == 0:
            # raise UF.CHBError(
                # "ARMBranch: no branch condition at " + iaddr)
            return (astree.mk_integer_constant(0), astree.mk_integer_constant(0))

        else:
            raise UF.CHBError(
                "ARMBranch: one or more than two conditions at " + iaddr)
