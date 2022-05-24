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
    Any, cast, Dict, List, Optional, Sequence, Tuple, TYPE_CHECKING, Union)

from chb.app.InstrXData import InstrXData

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

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
    from chb.api.CallTarget import CallTarget, AppTarget
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.simulation.SimulationState import SimulationState


@mipsregistry.register_tag("jalr", MIPSOpcode)
class MIPSJumpLinkRegister(MIPSOpcode):
    """JALR rd, rs

    Jump and Link Register
    Execute a procedure call to an instruction address in a register.

    args[0]: index of rd in mips dictionary
    args[1]: index of rs in mips dictionary
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        return [self.mipsd.mips_operand(i) for i in self.args]

    def has_string_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_string_reference for x in self.arguments(xdata)])

    def has_stack_arguments(self, xdata: InstrXData) -> bool:
        return any([x.is_stack_address for x in self.arguments(xdata)])

    def annotated_call_arguments(self, xdata: InstrXData) -> List[Dict[str, Any]]:
        return [x.to_annotated_value() for x in xdata.xprs]

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        return xdata.xprs

    def operand_values(self, xdata: InstrXData) -> Sequence[XXpr]:
        return self.arguments(xdata)

    def annotation(self, xdata: InstrXData) -> str:
        if xdata.has_call_target():
            args = ", ".join(str(x) for x in xdata.xprs)
            tgt = str(self.call_target(xdata))
            return "call " + tgt + "(" + args + ")"
        else:
            tgtx = str(xdata.xprs[0])
            return 'call* ' + tgtx

    def call_target(self, xdata: InstrXData) -> "CallTarget":
        if xdata.has_call_target():
            return xdata.call_target(self.ixd)
        else:
            raise UF.CHBError(
                "Instruction does not have a call target: " + str(self))

    def target_expr_ast(
            self,
            astree: ASTInterface,
            xdata: InstrXData) -> AST.ASTExpr:
        calltarget = xdata.call_target(self.ixd)
        tgtname = calltarget.name
        if calltarget.is_app_target:
            apptgt = cast("AppTarget", calltarget)
            return astree.mk_named_lval_expression(
                tgtname, globaladdress=int(str(apptgt.address), 16))
        else:
            return astree.mk_named_lval_expression(tgtname)

    def lhs_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            xdata: InstrXData) -> Tuple[AST.ASTLval, List[AST.ASTInstruction]]:

        def indirect_lhs(
                rtype: Optional[AST.ASTTyp]) -> Tuple[
                    AST.ASTLval, List[AST.ASTInstruction]]:
            tmplval = astree.mk_returnval_variable_lval(iaddr, rtype)
            tmprhs = astree.mk_lval_expr(tmplval)
            reglval = astree.mk_register_variable_lval("v0")
            return (tmplval, [astree.mk_assign(reglval, tmprhs)])

        calltarget = xdata.call_target(self.ixd)
        tgtname = calltarget.name
        models = ModelsAccess()
        if astree.has_symbol(tgtname) and astree.get_symbol(tgtname).vtype:
            fnsymbol = astree.get_symbol(tgtname)
            return indirect_lhs(fnsymbol.vtype)
        else:
            return indirect_lhs(None)

        return indirect_lhs(None)

    def ast(self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        if xdata.has_call_target():
            calltarget = xdata.call_target(self.ixd)
            tgtname = calltarget.name
            tgtxpr = self.target_expr_ast(astree, xdata)
            (lhs, assigns) = self.lhs_ast(astree, iaddr, xdata)
            args = self.arguments(xdata)
            argxprs: List[AST.ASTExpr] = []
            for arg in args:
                if XU.is_struct_field_address(arg, astree):
                    addr = XU.xxpr_to_struct_field_address_expr(arg, astree)
                elif arg.is_string_reference:
                    xprs = XU.xxpr_to_ast_exprs(arg, astree)
                    if len(xprs) != 1:
                        raise UF.CHBError(
                            "MIPSJumpLinkRegister: Multiple expressions for string constant")
                    else:
                        xpr = xprs[0]
                    cstr = arg.constant.string_reference()
                    saddr = hex(arg.constant.value)
                    argxprs.append(astree.mk_string_constant(xpr, cstr, saddr))
                elif arg.is_argument_value:
                    argindex = arg.argument_index()
                    funargs = astree.function_argument(argindex)
                    if len(funargs) > 1:
                        raise UF.CHBError(
                            "MIPSJumpLinkRegister: Multiple function arguments")
                    else:
                        funarg = funargs[0]
                    if funarg:
                        argxprs.append(astree.mk_lval_expr(funarg))
                    else:
                        astxpr = XU.xxpr_to_ast_exprs(arg, astree)
                        argxprs.extend(astxpr)
                else:
                    astxpr = XU.xxpr_to_ast_exprs(arg, astree)
                    argxprs.extend(astxpr)
            call = cast(AST.ASTInstruction, astree.mk_call(lhs, tgtxpr, argxprs))
            astree.add_instruction_span(call.instrid, iaddr, bytestring)
            for assign in assigns:
                astree.add_instruction_span(assign.instrid, iaddr, bytestring)
            return [call] + assigns
        else:
            return []

    @property
    def tgt_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   I: temp <- GPR[rs]
    #      GPR[rd] <- PC + 8
    #   I+1: if Config1[CA] = 0 then
    #            PC <- temp
    #        else
    #            PC <- temp[GPRLEN-1..1] || 0
    #            ISAMode <- temp[0]
    #        endif
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        tgtop = self.tgt_operand
        tgtval = simstate.rhs(iaddr, tgtop)
        simra = SSV.pc_to_return_address(
            simstate.programcounter.add_offset(8), simstate.function_address)
        simstate.increment_programcounter()
        simstate.registers['ra'] = simra

        if tgtval.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "jalr: target address is undefined: " + str(tgtop))

        tgtaddr: Union[SSV.SimGlobalAddress, SSV.SimDynamicLinkSymbol]
        if tgtval.is_address:
            tgtval = cast(SSV.SimAddress, tgtval)
            if tgtval.is_global_address:
                tgtaddr = cast(SSV.SimGlobalAddress, tgtval)
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "target address is not global: " + str(tgtval))

        # check if literal could be an address
        elif tgtval.is_literal:
            try:
                tgtaddr = simstate.resolve_literal_address(iaddr, tgtval.literal_value)
            except SU.CHBSimError as e:
                tgtaddr = SSV.mk_global_address(tgtval.literal_value, "external")

            if tgtaddr.is_undefined:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "jalr: target address cannot be resolved: " + str(tgtval))

        elif tgtval.is_dynamic_link_symbol:
            tgtaddr = cast(SSV.SimDynamicLinkSymbol, tgtval)

        elif tgtval.is_symbolic:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ("symbolic target address not recognized: " + str(tgtval)))
        else:
            raise SU.CHBSimCallTargetUnknownError(
                simstate, iaddr, tgtval, 'target = ' + str(tgtval))

        simstate.simprogramcounter.set_delayed_programcounter(tgtaddr)
        return SU.simcall(iaddr, simstate, tgtaddr, simra)
