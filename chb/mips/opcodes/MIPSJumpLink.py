# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
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
from chb.app.ASTNode import ASTInstruction, ASTExpr, ASTLval, ASTNoOffset

from chb.app.InstrXData import InstrXData

from chb.bctypes.BCTyp import BCTyp

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

from chb.mips.MIPSDictionaryRecord import mipsregistry
from chb.mips.MIPSOpcode import MIPSOpcode, simplify_result
from chb.mips.MIPSOperand import MIPSOperand

from chb.models.ModelsAccess import ModelsAccess
from chb.models.ModelsType import MNamedType

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget, AppTarget, StubTarget
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.simulation.SimulationState import SimulationState


@mipsregistry.register_tag("jal", MIPSOpcode)
class MIPSJumpLink(MIPSOpcode):
    """JAL target

    Jump and Link
    Execute a procedure call within the current 256MB-aligned region.

    args[0]: target
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        return [self.target]

    @property
    def target(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    def has_call_target(self, xdata: InstrXData) -> bool:
        return xdata.has_call_target()

    def call_target(self, xdata: InstrXData) -> "CallTarget":
        if xdata.has_call_target():
            return xdata.call_target(self.ixd)
        else:
            raise UF.CHBError("Call target not found for " + str(self))

    def has_string_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_string_reference for x in self.arguments(xdata)])

    def has_stack_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_stack_address for x in self.arguments(xdata)])

    def annotated_call_arguments(
            self, xdata: InstrXData) -> Sequence[Dict[str, Any]]:
        return [x.to_annotated_value() for x in self.arguments(xdata)]

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        return xdata.xprs

    def annotation(self, xdata: InstrXData) -> str:
        cargs = ", ".join(str(x) for x in self.arguments(xdata))
        if self.has_call_target(xdata):
            tgt = self.call_target(xdata)
            if tgt.is_app_target:
                tgt = cast("AppTarget", tgt)
                return "call " + str(tgt.address) + "(" + cargs + ")"
            elif tgt.is_so_target:
                tgt = cast("StubTarget", tgt)
                return "call " + str(tgt) + "(" + cargs + ")"
            else:
                return "call " + str(self.target) + "(" + cargs + ")"
        else:
            return "call " + str(self.target) + "(" + cargs + ")"

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
            reglval = astree.mk_register_variable_lval("v0")
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

    def ast(self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[ASTInstruction]:
        if xdata.has_call_target():
            calltarget = xdata.call_target(self.ixd)
            tgtname = calltarget.name
            tgtxpr = self.target_expr_ast(astree, xdata)
            (lhs, assigns) = self.lhs_ast(astree, iaddr, xdata)
            args = self.arguments(xdata)
            argxprs: List[ASTExpr] = []
            for arg in args:
                if XU.is_struct_field_address(arg, astree):
                    addr = XU.xxpr_to_struct_field_address_expr(arg, astree)
                elif arg.is_string_reference:
                    xpr = XU.xxpr_to_ast_expr(arg, astree)
                    cstr = arg.constant.string_reference()
                    saddr = hex(arg.constant.value)
                    argxprs.append(astree.mk_string_constant(xpr, cstr, saddr))
                elif arg.is_argument_value:
                    argindex = arg.argument_index()
                    funarg = astree.function_argument(argindex)
                    if funarg:
                        astxpr = astree.mk_register_variable_expr(
                            funarg.name, vtype=funarg.typ, parameter=argindex)
                        argxprs.append(astxpr)
                    else:
                        astxpr = XU.xxpr_to_ast_expr(arg, astree)
                        argxprs.append(astxpr)
                else:
                    astxpr = XU.xxpr_to_ast_expr(arg, astree)
                    argxprs.append(astxpr)
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
            return []

    # ----------------------------------------------------------------------
    # Operation:
    #   I: GPR[31] <- PC + 8
    #   I+1: PC <- PC[GPRLEN..28] || instr_index || 0[2]
    # ----------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        tgtaddr = self.target.absolute_address_value
        tgt = simstate.resolve_literal_address(iaddr, tgtaddr)
        simstate.increment_programcounter()
        simra = SSV.pc_to_return_address(
            simstate.programcounter.add_offset(4), simstate.function_address)
        simstate.registers["ra"] = simra
        simstate.simprogramcounter.set_delayed_programcounter(tgt)
        return SU.simcall(iaddr, simstate, tgt, simra)
