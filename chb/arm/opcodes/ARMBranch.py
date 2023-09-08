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

if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget, AppTarget, StaticStubTarget
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.VConstantValueVariable import VFunctionReturnValue


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

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[1] == 1 else ""
        return cc + wide

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

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

        if xdata.has_inlined_call_target():
            astree.add_diagnostic("Inlined call omitted at " + iaddr)
            return ([], [])

        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        tgt = self.operands[0]
        if tgt.is_absolute:
            tgtaddr = cast(ARMAbsoluteOp, tgt.opkind)
            faddr = tgtaddr.address.get_hex()
            if self.app.has_function_name(tgtaddr.address.get_hex()):
                fnsymbol = self.app.function_name(faddr)
                if astree.globalsymboltable.has_symbol(fnsymbol):
                    tgtvinfo = astree.globalsymboltable.get_symbol(fnsymbol)
                    tgtxpr: AST.ASTExpr = astree.mk_vinfo_lval_expression(tgtvinfo)
                else:
                    tgtxpr = astree.mk_global_variable_expr(
                        fnsymbol, globaladdress=int(str(tgtaddr.address), 16))
            else:
                (tgtxpr, _, _) = self.operands[0].ast_rvalue(astree)
        else:
            (tgtxpr, _, _) = self.operands[0].ast_rvalue(astree)

        ll_lhs = (
            astree.mk_register_variable_lval("S0")
            if len(xdata.xprs) > 0 and str(xdata.xprs[0]) == "S0"
            else astree.mk_register_variable_lval("R0"))

        ll_call = astree.mk_call(
            ll_lhs,
            tgtxpr,
            [],
            iaddr=iaddr,
            bytestring=bytestring)

        tgt_returntype = None
        tgt_argtypes: Sequence[AST.ASTTyp] = []
        tgt_argcount = -1
        tgt_xprtype = tgtxpr.ctype(astree.ctyper)
        if tgt_xprtype is not None:
            if tgt_xprtype.is_function:
                tgt_xprtype = cast(AST.ASTTypFun, tgt_xprtype)
                tgt_returntype = astree.resolve_type(tgt_xprtype.returntyp)
                if (not tgt_xprtype.is_varargs) and tgt_xprtype.argtypes is not None:
                    tgt_funargs = tgt_xprtype.argtypes.funargs
                    tgt_argtypes = [f.argtyp for f in tgt_funargs]
                    tgt_argcount = len(tgt_argtypes)

        if tgt_returntype is None:
            if len(defuses) == 0 or defuses[0] is None:
                hl_lhs: Optional[AST.ASTLval] = None
            else:
                if len(xdata.vars) > 0:
                    returnvar = xdata.vars[0]
                    returnval = cast("VFunctionReturnValue", returnvar.denotation.auxvar)
                    hl_lhs = XU.vfunctionreturn_value_to_ast_lvals(
                        returnval, xdata, astree)[0]
                else:
                    returnvarname = "rtn_" + iaddr
                    astreturnvar = astree.mk_named_variable(returnvarname)
                    hl_lhs = astree.mk_lval(astreturnvar, nooffset)

        else:
            if tgt_returntype.is_void or defuses[0] is None:
                hl_lhs = None
            else:
                if len(xdata.vars) > 0:
                    returnvar = xdata.vars[0]
                    returnval = cast("VFunctionReturnValue", returnvar.denotation.auxvar)
                    hl_lhs = XU.vfunctionreturn_value_to_ast_lvals(
                        returnval, xdata, astree)[0]
                else:
                    returnvarname = "rtn_" + iaddr
                    astreturnvar = astree.mk_named_variable(returnvarname, vtype=tgt_returntype)
                    hl_lhs = astree.mk_lval(astreturnvar, nooffset)

        if not (self.is_call(xdata) and xdata.has_call_target()):
            raise UF.CHBError(name + " at " + iaddr + ": Call without call target")

        callargs = self.arguments(xdata)
        if tgt_argcount == -1:
            argcount = len(callargs)
            argtypes: Sequence[Optional[AST.ASTTyp]] = [None] * argcount
        else:
            argcount = tgt_argcount
            argtypes = tgt_argtypes

        annotations: List[str] = [iaddr, "BL"]

        argregs = ["R0", "R1", "R2", "R3"][:argcount]
        argxprs: List[AST.ASTExpr] = []
        for (i, (reg, arg, argtype)) in enumerate(zip(argregs, callargs, argtypes)):
            if arg.is_string_reference:
                regast = astree.mk_register_variable_expr(reg)
                cstr = arg.constant.string_reference()
                saddr = hex(arg.constant.value)
                argxprs.append(astree.mk_string_constant(regast, cstr, saddr))
                if len(rdefs) > i:
                    astree.add_expr_reachingdefs(regast, [rdefs[i]])
            elif arg.is_argument_value:
                argindex = arg.argument_index()
                try:
                    funargs = astree.function_argument(argindex)
                except UF.CHBError as e:
                    break
                if len(funargs) == 0:
                    astree.add_diagnostic(
                        "BL ("
                        + iaddr
                        + "): no function argument for index "
                        + str(argindex)
                        + " in call to "
                        + str(tgtxpr))
                    funarg: Optional[AST.ASTLval] = None

                elif len(funargs) > 1:
                    astree.add_diagnostic(
                        "BL ("
                        + iaddr
                        + "): multiple values for function argument for index "
                        + str(argindex)
                        + " in call to "
                        + str(tgtxpr)
                        + ": "
                        + ", ".join(str(x) for x in funargs))
                    funarg = None
                else:
                    funarg = funargs[0]

                if funarg is not None:
                    argxprs.append(astree.mk_lval_expr(funarg))
                else:
                    argxprs.append(astree.mk_register_variable_expr(reg))
            else:
                if arg.is_register_variable:
                    astops = XU.xxpr_to_ast_def_exprs(arg, xdata, iaddr, astree)
                    if len(astops) == 1:
                        argxprs.append(astops[0])
                    else:
                        astxprs = XU.xxpr_to_ast_def_exprs(arg, xdata, iaddr, astree)
                        if len(astxprs) == 0:
                            raise UF.CHBError(
                                name +
                                ": No ast value for call argument at " + iaddr)
                        if len(astxprs) > 1:
                            raise UF.CHBError(
                                name
                                + ": Multiple rhs values for call argument at "
                                + iaddr
                                + ": "
                                + ", ".join(str(a) for a in argxprs))
                        argxprs.append(astxprs[0])
                else:
                    if arg.is_stack_address and argtype is not None:
                        arg = cast(XprCompound, arg)
                        stackoffset = arg.stack_address_offset()
                        arglval = astree.mk_stack_variable_lval(
                            stackoffset, vtype=argtype)
                        argexpr = astree.mk_address_of(arglval)
                        argxprs.append(argexpr)
                    else:
                        astxprs = XU.xxpr_to_ast_exprs(arg, xdata, iaddr, astree)
                        if len(astxprs) == 0:
                            raise UF.CHBError(
                                name
                                + ":No ast value for call argument at "
                                + iaddr)
                        if len(astxprs) > 1:
                            raise UF.CHBError(
                                name
                                + ": Multiple rhs values for call argument at "
                                + iaddr
                                + ": "
                                + ", ".join(str(a) for a in argxprs))

                        argxprs.append(astxprs[0])

        hl_call = cast(AST.ASTInstruction, astree.mk_call(
            hl_lhs,
            tgtxpr,
            argxprs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations))

        astree.add_instr_mapping(hl_call, ll_call)
        astree.add_instr_address(hl_call, [iaddr])
        for (i, argxpr) in enumerate(argxprs):
            if len(rdefs) > i:
                astree.add_expr_reachingdefs(argxpr, [rdefs[i]])
        if hl_lhs is not None:
            astree.add_lval_mapping(hl_lhs, ll_lhs)
            astree.add_lval_defuses(hl_lhs, defuses[0])
            astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        if str(ll_lhs) == "S0" and hl_lhs is not None:
            hl_lhsx = astree.mk_lval_expr(hl_lhs)
            hl_var_assign = astree.mk_assign(
                ll_lhs,
                hl_lhsx,
                iaddr=iaddr,
                annotations=annotations)

            astree.add_reg_definition(iaddr, ll_lhs, hl_lhsx)
            astree.add_instr_mapping(hl_var_assign, ll_call)

            return ([hl_call, hl_var_assign], [ll_call])

        else:
            return ([hl_call], [ll_call])


    '''
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
    '''
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
            astconds = XU.xxpr_to_ast_exprs(condition, xdata, iaddr, astree)
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
                csetter = xdata.tags[2]
                astconditions = XU.xxpr_to_ast_def_exprs(condition, xdata, csetter, astree)
                if len(astconditions) == 1:
                    hl_astcond = astconditions[0]
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
            astree.add_diagnostic(iaddr + ": no branch condition found")
            return (astree.mk_integer_constant(0), astree.mk_integer_constant(0))

        else:
            raise UF.CHBError(
                "ARMBranch: one or more than two conditions at " + iaddr)
