# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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

from typing import Any, cast, Dict, List, Sequence, TYPE_CHECKING

from chb.api.CallTarget import CallTarget

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree
from chb.app.ASTNode import ASTInstruction, ASTExpr

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree
from chb.app.ASTNode import ASTInstruction, ASTExpr

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand
from chb.arm.ARMOperandKind import ARMOperandKind, ARMAbsoluteOp

from chb.invariants.XXpr import XXpr

from chb.models.ModelsAccess import ModelsAccess
from chb.models.ModelsType import MNamedType

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
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

    def assembly_ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[ASTInstruction]:
        lhs = astree.mk_variable_lval("R0")
        tgt = self.operands[0]
        if tgt.is_absolute:
            tgtaddr = cast(ARMAbsoluteOp, tgt.opkind)
            if self.app.has_function_name(tgtaddr.address.get_hex()):
                faddr = tgtaddr.address.get_hex()
                fnsymbol = self.app.function_name(faddr)
                tgtxpr: ASTExpr = astree.mk_variable_expr(fnsymbol)
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
            models = ModelsAccess()
            tgt = str(xdata.call_target(self.ixd))
            if tgt.startswith("App:"):
                tgt = tgt[4:]
            if models.has_so_function_summary(tgt):
                summary = models.so_function_summary(tgt)
                returntype = summary.signature.returntype
                if returntype.is_named_type:
                    returntype = cast(MNamedType, returntype)
                    typename = returntype.typename
                    if typename == "void" or typename == "VOID":
                        lhs = astree.mk_ignored_lval()
                    else:
                        lhs = astree.mk_variable_lval("R0")
                else:
                    lhs = astree.mk_variable_lval("R0")
            else:
                lhs = astree.mk_variable_lval("R0")
            tgtxpr = astree.mk_variable_expr(tgt)
            args = self.arguments(xdata)
            argregs = ["R0", "R1", "R2", "R3"]
            callargs = argregs[:len(args)]
            argxprs: List[ASTExpr] = []
            for (reg, arg) in zip(callargs, args):
                if arg.is_string_reference:
                    regast = astree.mk_variable_expr(reg)
                    cstr = arg.constant.string_reference()
                    saddr = hex(arg.constant.value)
                    argxprs.append(astree.mk_string_constant(regast, cstr, saddr))
                else:
                    argxprs.append(astree.mk_variable_expr(reg))
            call = astree.mk_call(lhs, tgtxpr, argxprs)
            astree.add_instruction_span(call.id, iaddr, bytestring)
            return [call]
        else:
            return self.assembly_ast(astree, iaddr, bytestring, xdata)
