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

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

from chb.models.ModelsAccess import ModelsAccess
from chb.models.ModelsType import MNamedType

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget, AppTarget, StaticStubTarget
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("BL", ARMOpcode)
class ARMBranchLink(ARMOpcode):
    """Calls a subroutine at a PC-relative address.

    tags[1]: <c>
    args[0]: index of target operand in armdictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 1, "BranchLink")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    def has_string_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_string_reference for x in self.arguments(xdata)])

    def has_stack_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_stack_address for x in self.arguments(xdata)])

    def annotated_call_arguments(
            self, xdata: InstrXData) -> Sequence[Dict[str, Any]]:
        return [x.to_annotated_value() for x in xdata.xprs]

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        return xdata.xprs

    def is_call(self, xdata: InstrXData) -> bool:
        return len(xdata.tags) == 2 and xdata.tags[1] == "call"

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        return xdata.has_call_target()

    def annotation(self, xdata: InstrXData) -> str:
        """data formats: call, jumptable, indirect jump

        call: [a:..., 'call'], <args> + <index of call-target in ixd>

        or

        xdata format: a:x .

        xprs[0]: target operand
        """

        if self.is_call(xdata) and xdata.has_call_target():
            tgt = xdata.call_target(self.ixd)
            args = ", ".join(str(x) for x in self.arguments(xdata))
            return "call " + str(tgt) + "(" + args + ")"

        ctgt = str(xdata.xprs[0])
        return "call " + ctgt

    def call_target(self, xdata: InstrXData) -> "CallTarget":
        if self.is_call(xdata):
            return xdata.call_target(self.ixd)
        else:
            raise UF.CHBError("Instruction is not a call: " + str(self))

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
        elif calltarget.is_static_stub_target:
            stubtgt = cast("StaticStubTarget", calltarget)
            return astree.mk_global_variable_expr(
                tgtname, globaladdress=int(str(stubtgt.address), 16))
        else:
            return astree.mk_global_variable_expr(tgtname)

    def lhs_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[AST.ASTLval, List[AST.ASTInstruction]]:

        def indirect_lhs(
                rtype: Optional[AST.ASTTyp]) -> Tuple[AST.ASTLval, List[AST.ASTInstruction]]:
            tmplval = astree.mk_returnval_variable_lval(iaddr, rtype)
            tmprhs = astree.mk_lval_expr(tmplval)
            reglval = astree.mk_register_variable_lval("R0")
            assign = astree.mk_assign(
                reglval, tmprhs, iaddr=iaddr, bytestring=bytestring)
            return (tmplval, [assign])

        calltarget = xdata.call_target(self.ixd)
        tgtname = calltarget.name
        models = ModelsAccess()
        if astree.has_symbol(tgtname) and astree.get_symbol(tgtname).vtype:
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
        call = astree.mk_call(lhs, tgtxpr, [], iaddr=iaddr, bytestring=bytestring)
        return [call]

    def ast(self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        if self.is_call(xdata) and xdata.has_call_target():
            calltarget = xdata.call_target(self.ixd)
            tgtname = calltarget.name
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
                    if len(funargs) == 0:
                        astree.add_diagnostic(
                            "No function argument extracted for "
                            + str(arg)
                            + " in function call to "
                            + tgtname
                            + " at address "
                            + iaddr)
                        argxprs.append(astree.mk_register_variable_expr(reg))
                    elif len(funargs) > 1:
                        raise UF.CHBError(
                            "ARMBranchLink: multiple function arguments "
                            + "for call to "
                            + tgtname
                            + " and argument "
                            + str(arg)
                            + ": "
                            + ", ".join(str(a) for a in funargs))
                    else:
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
            return self.assembly_ast(astree, iaddr, bytestring, xdata)

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "BL"]

        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        tgt = self.operands[0]
        if tgt.is_absolute:
            tgtaddr = cast(ARMAbsoluteOp, tgt.opkind)
            faddr = tgtaddr.address.get_hex()
            if self.app.has_function_name(tgtaddr.address.get_hex()):
                fnsymbol = self.app.function_name(faddr)
                tgtxpr: AST.ASTExpr = astree.mk_global_variable_expr(
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
        tgt_argcount = -1
        tgt_xprtype = tgtxpr.ctype(astree.ctyper)
        if tgt_xprtype is not None:
            if tgt_xprtype.is_function:
                tgt_xprtype = cast(AST.ASTTypFun, tgt_xprtype)
                tgt_returntype = astree.resolve_type(tgt_xprtype.returntyp)
                if (not tgt_xprtype.is_varargs) and tgt_xprtype.argtypes is not None:
                    argtypes = tgt_xprtype.argtypes.funargs
                    tgt_argcount = len(argtypes)

        if tgt_returntype is None:
            hl_lhs: Optional[AST.ASTLval] = ll_lhs
        else:
            if tgt_returntype.is_void or defuses[0] is None:
                hl_lhs = None
            else:
                hl_lhs = astree.mk_returnval_variable_lval(iaddr, vtype=tgt_returntype) 

        if not (self.is_call(xdata) and xdata.has_call_target()):
            raise UF.CHBError("BL at " + iaddr + ": Call without call target")

        callargs = self.arguments(xdata)
        if tgt_argcount == -1:
            argcount = len(callargs)
        else:
            argcount = tgt_argcount
        argregs = ["R0", "R1", "R2", "R3"][:argcount]
        argxprs: List[AST.ASTExpr] = []
        for (reg, arg) in zip(argregs, callargs):
            if arg.is_string_reference:
                regast = astree.mk_register_variable_expr(reg)
                cstr = arg.constant.string_reference()
                saddr = hex(arg.constant.value)
                argxprs.append(astree.mk_string_constant(regast, cstr, saddr))
            elif arg.is_argument_value:
                argindex = arg.argument_index()
                funargs = astree.function_argument(argindex)
                if len(funargs) != 1:
                    raise UF.CHBError(
                        "BL: no or multiple function arguments")
                funarg = funargs[0]
                if funarg:
                    argxprs.append(astree.mk_lval_expr(funarg))
                else:
                    argxprs.append(astree.mk_register_variable_expr(reg))
            else:
                if arg.is_register_variable:
                    astops = XU.xxpr_to_ast_def_exprs(arg, xdata, iaddr, astree)
                    if len(astops) == 1:
                        argxprs.append(astops[0])
                    else:
                        astxprs = XU.xxpr_to_ast_exprs(arg, xdata, astree)
                        if len(astxprs) == 0:
                            raise UF.CHBError("No ast value for call argument at " + iaddr)
                        if len(astxprs) > 1:
                            raise UF.CHBError(
                                "Multiple rhs values for call argument at "
                                + iaddr
                                + ": "
                                + ", ".join(str(a) for a in argxprs))
                        argxprs.append(astxprs[0])
                else:
                    astxprs = XU.xxpr_to_ast_exprs(arg, xdata, astree)
                    if len(astxprs) == 0:
                        raise UF.CHBError("No ast value for call argument at " + iaddr)
                    if len(astxprs) > 1:
                        raise UF.CHBError(
                            "Multiple rhs values for call argument at "
                            + iaddr
                            + ": "
                            + ", ".join(str(a) for a in argxprs))
                    argxprs.append(astxprs[0])

        hl_call = cast(AST.ASTInstruction, astree.mk_call(
            hl_lhs, tgtxpr, argxprs, iaddr=iaddr, bytestring=bytestring))

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
