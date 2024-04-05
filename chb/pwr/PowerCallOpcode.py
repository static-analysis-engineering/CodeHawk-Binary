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

from typing import (
    Any, cast, Dict, List, Optional, Sequence, Tuple, TYPE_CHECKING)

from chb.app.InstrXData import InstrXData

from chb.ast.AbstractSyntaxTree import nooffset
import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.bctypes.BCTyp import BCTyp

from chb.invariants.XXpr import XXpr, XprCompound
import chb.invariants.XXprUtil as XU

from chb.pwr.PowerDictionaryRecord import pwrregistry
from chb.pwr.PowerOpcode import PowerOpcode
from chb.pwr.PowerOperand import PowerOperand
from chb.pwr.PowerOperandKind import PowerOperandKind, PowerAbsoluteOp

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget, AppTarget, StaticStubTarget
    from chb.pwr.PowerDictionary import PowerDictionary
    from chb.invariants.VConstantValueVariable import VFunctionReturnValue


class PowerCallOpcode(PowerOpcode):
    """Generic call functionality.

    """

    def __init__(
            self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOpcode.__init__(self, pwrd, ixval)

    @property
    def operands(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(self.args[0])]

    @property
    def opargs(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(i) for i in self.args]

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
        return len(xdata.tags) >= 2 and xdata.tags[1] == "call"

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        return xdata.has_call_target()

    def annotation(self, xdata: InstrXData) -> str:
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

    def ast_call_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            name: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        if xdata.has_inlined_call_target():
            chklogger.logger.info("Inlined call omitted at %s", iaddr)
            return ([], [])

        annotations: List[str] = [iaddr, "BL"]

        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        tgt = self.operands[0]
        if tgt.is_absolute:
            tgtaddr = cast(PowerAbsoluteOp, tgt.opkind)
            faddr = tgtaddr.address.get_hex()
            if self.app.has_function_name(tgtaddr.address.get_hex()):
                fnsymbol = self.app.function_name(faddr)
                if astree.globalsymboltable.has_symbol(fnsymbol):
                    tgtvinfo = astree.globalsymboltable.get_symbol(fnsymbol)
                    tgtxpr: AST.ASTExpr = astree.mk_vinfo_lval_expression(
                        tgtvinfo)
                else:
                    tgtxpr = astree.mk_global_variable_expr(
                        fnsymbol, globaladdress=int(str(tgtaddr.address), 16))
            else:
                (tgtxpr, _, _) = self.operands[0].ast_rvalue(astree)
        else:
            (tgtxpr, _, _) = self.operands[0].ast_rvalue(astree)

        ll_lhs = (astree.mk_register_variable_lval("r3"))

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
                if (
                        (not tgt_xprtype.is_varargs)
                        and tgt_xprtype.argtypes is not None):
                    tgt_funargs = tgt_xprtype.argtypes.funargs
                    tgt_argtypes = [f.argtyp for f in tgt_funargs]
                    tgt_argcount = len(tgt_argtypes)

        if tgt_returntype is None:
            if len(defuses) == 0 or defuses[0] is None:
                hl_lhs: Optional[AST.ASTLval] = None
            else:
                if len(xdata.vars) > 0:
                    returnvar = xdata.vars[0]
                    returnval = cast(
                        "VFunctionReturnValue", returnvar.denotation.auxvar)
                    hl_lhs = XU.vfunctionreturn_value_to_ast_lvals(
                        returnval, xdata, astree)[0]
                else:
                    returnvarname = "rtn_" + iaddr
                    astreturnvar = astree.mk_named_variable(returnvarname)
                    hl_lhs = astree.mk_lval(astreturnvar, nooffset)

        else:
            if tgt_returntype.is_void:
                hl_lhs = None
            else:
                if len(xdata.vars) > 0:
                    returnvar = xdata.vars[0]
                    returnval = cast(
                        "VFunctionReturnValue", returnvar.denotation.auxvar)
                    hl_lhs = XU.vfunctionreturn_value_to_ast_lvals(
                        returnval, xdata, astree)[0]
                else:
                    returnvarname = "rtn_" + iaddr
                    astreturnvar = astree.mk_named_variable(
                        returnvarname, vtype=tgt_returntype)
                    hl_lhs = astree.mk_lval(astreturnvar, nooffset)

        if not (self.is_call(xdata) and xdata.has_call_target()):
            raise UF.CHBError(
                name + " at " + iaddr + ": Call without call target")

        callargs = self.arguments(xdata)
        if tgt_argcount == -1:
            argcount = len(callargs)
            argtypes: Sequence[Optional[AST.ASTTyp]] = [None] * argcount
        else:
            argcount = tgt_argcount
            argtypes = tgt_argtypes

        argregs = ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"][:argcount]
        argxprs: List[AST.ASTExpr] = []
        for (i, (reg, arg, argtype)) in enumerate(
                zip(argregs, callargs, argtypes)):
            if arg.is_string_reference:
                regast = astree.mk_register_variable_expr(reg)
                cstr = arg.constant.string_reference()
                saddr = hex(arg.constant.value)
                argxprs.append(astree.mk_string_constant(regast, cstr, saddr))
                if len(rdefs) > i:
                    astree.add_expr_reachingdefs(regast, [rdefs[i]])
            elif arg.is_argument_value:
                argindex = arg.argument_index()
                funargs = astree.function_argument(argindex)
                if len(funargs) != 1:
                    raise UF.CHBError(
                        name
                        + "; "
                        + iaddr
                        + ": no or multiple function arguments: "
                        + str(tgtxpr)
                        + " (index: "
                        + str(argindex)
                        + "): "
                        + ", ".join(str(x) for x in funargs)
                    )
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
                        astxprs = XU.xxpr_to_ast_def_exprs(
                            arg, xdata, iaddr, astree)
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

        return ([hl_call], [ll_call])
