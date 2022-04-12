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

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree
from chb.app.ASTNode import ASTInstruction, ASTExpr, ASTLval

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree
from chb.app.ASTNode import ASTInstruction, ASTExpr

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand
from chb.arm.ARMOperandKind import ARMOperandKind, ARMAbsoluteOp

from chb.bctypes.BCTyp import BCTyp

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

from chb.models.ModelsAccess import ModelsAccess
from chb.models.ModelsType import MNamedType

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget, AppTarget
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("BLX", ARMOpcode)
class ARMBranchLinkExchange(ARMOpcode):
    """Calls a subroutine at a PC-relative address.

    tags[1]: <c>
    args[0]: index of target operand in armdictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 1, "BranchLinkExchange")

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
        return xdata.has_call_target()

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        return xdata.has_call_target()

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:x .

        xprs[0]: target operand
        """

        if self.is_call(xdata) and xdata.has_call_target():
            tgt = xdata.call_target(self.ixd)
            args = ", ".join(str(x) for x in self.arguments(xdata))
            return "call " + str(tgt) + "(" + args + ")"

        else:
            ctgt = str(xdata.xprs[0])
            args = ", ".join(str(xdata.xprs[i]) for i in [1, 2, 3, 4])
            return "call " + ctgt + "(" + args + ")"

    def call_target(self, xdata: InstrXData) -> "CallTarget":
        if xdata.has_call_target():
            return xdata.call_target(self.ixd)
        else:
            raise UF.CHBError("Instruction is not a call: " + str(self))

    def target_expr_ast(
            self,
            astree: AbstractSyntaxTree,
            xdata: InstrXData) -> ASTExpr:
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
            astree: AbstractSyntaxTree,
            iaddr: str,
            xdata: InstrXData) -> Tuple[ASTLval, List[ASTInstruction]]:

        def indirect_lhs(
                rtype: Optional[BCTyp]) -> Tuple[ASTLval, List[ASTInstruction]]:
            tmplval = astree.mk_returnval_variable_lval(iaddr, rtype)
            tmprhs = astree.mk_lval_expr(tmplval)
            reglval = astree.mk_register_variable_lval("R0")
            return (tmplval, [astree.mk_assign(reglval, tmprhs)])

        calltarget = xdata.call_target(self.ixd)
        tgtname = calltarget.name
        models = ModelsAccess()
        if astree.has_symbol(tgtname) and astree.symbol(tgtname).vtype:
            fnsymbol = astree.symbol(tgtname)
            if fnsymbol.returns_void:
                return (astree.mk_ignored_lval(), [])
            else:
                return indirect_lhs(fnsymbol.vtype)
        elif models.has_so_function_summary(tgtname):
            summary = models.so_function_summary(tgtname)
            returntype = summary.signature.returntype
            if returntype.is_named_type:
                returntype = cast(MNamedType, returntype)
                typename = returntype.typename
                if typename == "void" or typename == "VOID":
                    return (astree.mk_ignored_lval(), [])
                else:
                    return indirect_lhs(None)
            else:
                return indirect_lhs(None)
        else:
            return indirect_lhs(None)

    def assembly_ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[ASTInstruction]:
        lhs = astree.mk_register_variable_lval("R0")
        tgt = self.operands[0]
        if tgt.is_absolute:
            tgtaddr = cast(ARMAbsoluteOp, tgt.opkind)
            if self.app.has_function_name(tgtaddr.address.get_hex()):
                faddr = tgtaddr.address.get_hex()
                fnsymbol = self.app.function_name(faddr)
                tgtxpr: ASTExpr = astree.mk_global_variable_expr(
                    fnsymbol, globaladdress=int(str(tgtaddr.address), 16))
            else:
                (tgtxpr, _, _) = self.operands[0].ast_rvalue(astree)
        else:
            (tgtxpr, _, _) = self.operands[0].ast_rvalue(astree)
        call = astree.mk_call(lhs, tgtxpr, [])
        astree.add_instruction_span(call.id, iaddr, bytestring)
        return [call]

    def ast(self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[ASTInstruction]:
        if self.is_call(xdata) and xdata.has_call_target():
            tgtxpr = self.target_expr_ast(astree, xdata)
            (lhs, assigns) = self.lhs_ast(astree, iaddr, xdata)
            args = self.arguments(xdata)
            argregs = ["R0", "R1", "R2", "R3"]
            callargs = argregs[:len(args)]
            argxprs: List[ASTExpr] = []
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
                            "ARMBranchLinkExchange: no or multiple function arguments")
                    funarg = funargs[0]
                    if funarg:
                        argxprs.append(astree.mk_lval_expr(funarg))
                    else:
                        argxprs.append(astree.mk_register_variable_expr(reg))
                else:
                    argxprs.append(astree.mk_register_variable_expr(reg))
            if len(args) > 4:
                for a in args[4:]:
                    argxprs.extend(XU.xxpr_to_ast_exprs(a, astree))
            if lhs.is_ignored:
                call: ASTInstruction = astree.mk_call(lhs, tgtxpr, argxprs)
                astree.add_instruction_span(call.id, iaddr, bytestring)
                return [call]
            else:
                call = cast(ASTInstruction, astree.mk_call(lhs, tgtxpr, argxprs))
                astree.add_instruction_span(call.id, iaddr, bytestring)
                for assign in assigns:
                    astree.add_instruction_span(assign.id, iaddr, bytestring)
                return [call] + assigns
        else:
            return self.assembly_ast(astree, iaddr, bytestring, xdata)
