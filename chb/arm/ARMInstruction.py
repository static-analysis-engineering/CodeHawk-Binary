# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2025  Aarno Labs LLC
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

import xml.etree.ElementTree as ET

from typing import (
    Any, Callable, cast, Dict, List, Optional, Sequence, Tuple, TYPE_CHECKING)

from chb.api.CallTarget import CallTarget

from chb.app.FunctionDictionary import FunctionDictionary
from chb.app.Instruction import Instruction
from chb.app.InstrXData import InstrXData
from chb.app.MemoryAccess import MemoryAccess
from chb.app.Operand import Operand
from chb.app.StackPointerOffset import StackPointerOffset

from chb.ast.ASTNode import ASTNode, ASTInstruction, ASTExpr
from chb.astinterface.ASTInterface import ASTInterface

from chb.arm.ARMDictionary import ARMDictionary
from chb.arm.ARMOpcode import ARMOpcode
from chb.arm.ARMOperand import ARMOperand
from chb.arm.opcodes.ARMBranch import ARMBranch
from chb.arm.opcodes.ARMIfThen import ARMIfThen

from chb.invariants.InvariantFact import InvariantFact
from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.arm.ARMBlock import ARMBlock
    from chb.arm.ARMFunction import ARMFunction
    from chb.arm.ARMJumpTable import ARMJumpTable
    from chb.bctypes.BCTyp import BCTyp


class ARMInstruction(Instruction):

    def __init__(self, armblock: "ARMBlock", xnode: ET.Element) -> None:
        Instruction.__init__(self, xnode)
        self._armblock = armblock
        self._opcode: Optional[ARMOpcode] = None
        self._opcodetext: Optional[str] = None
        self._xdata: Optional[InstrXData] = None

    @property
    def armblock(self) -> "ARMBlock":
        return self._armblock

    @property
    def armfunction(self) -> "ARMFunction":
        return self.armblock.armfunction

    @property
    def armdictionary(self) -> ARMDictionary:
        return self.armblock.armdictionary

    @property
    def app(self) -> "AppAccess":
        return self.armfunction.app

    @property
    def armfunctiondictionary(self) -> "FunctionDictionary":
        return self.armfunction.armfunctiondictionary

    @property
    def opcode(self) -> ARMOpcode:
        if self._opcode is None:
            self._opcode = self.armdictionary.read_xml_arm_opcode(self.xnode)
        return self._opcode

    def has_control_flow(self) -> bool:
        brcc = self.xnode.get("brcc")
        return brcc is not None

    @property
    def xdata(self) -> InstrXData:
        if self._xdata is None:
            self._xdata = self.armfunctiondictionary.read_xml_instrx(self.xnode)
        return self._xdata

    @property
    def mnemonic_stem(self) -> str:
        return self.opcode.mnemonic_stem

    @property
    def mnemonic(self) -> str:
        return self.opcode.mnemonic + self.opcode.mnemonic_extension()

    @property
    def lhs(self) -> Sequence[XVariable]:
        return self.opcode.lhs(self.xdata)

    @property
    def rhs(self) -> Sequence[XXpr]:
        return self.opcode.rhs(self.xdata)

    @property
    def opcodetext(self) -> str:
        try:
            return self.mnemonic.ljust(14) + " " + self.operandstring
        except IT.IndexedTableError as e:
            opcode = self.armdictionary.read_xml_arm_opcode(self.xnode)
            raise UF.CHBError(
                "Error for ARM opcode "
                + str(opcode)
                + " in function: "
                + self.armfunction.faddr
                + " at address "
                + self.iaddr
                + ": "
                + str(e))

    @property
    def operands(self) -> Sequence[ARMOperand]:
        return self.opcode.operands

    @property
    def operandstring(self) -> str:
        return self.opcode.operandstring

    @property
    def bytestring(self) -> str:
        return self.armdictionary.read_xml_arm_bytestring(self.xnode)

    @property
    def is_call_instruction(self) -> bool:
        return self.opcode.is_call_instruction(self.xdata)

    @property
    def is_jump_instruction(self) -> bool:
        return self.is_branch_instruction

    def has_call_target(self) -> bool:
        return self.xdata.has_call_target()

    @property
    def is_load_instruction(self) -> bool:
        return self.opcode.is_load_instruction(self.xdata)

    @property
    def is_store_instruction(self) -> bool:
        return self.opcode.is_store_instruction(self.xdata)

    @property
    def is_return_instruction(self) -> bool:
        return self.opcode.is_return_instruction(self.xdata)

    @property
    def is_conditional_return_instruction(self) -> bool:
        return self.opcode.is_conditional_return_instruction(self.xdata)

    @property
    def is_nop_instruction(self) -> bool:
        return self.opcode.is_nop_instruction(self.xdata)

    def return_value(self) -> Optional[XXpr]:
        if self.is_return_instruction:
            return self.opcode.return_value(self.xdata)
        else:
            return None

    @property
    def is_branch_instruction(self) -> bool:
        return self.opcode.is_branch_instruction

    @property
    def invariants(self) -> Sequence[InvariantFact]:
        fn_invariants = self.armfunction.invariants
        if self.iaddr in fn_invariants:
            return fn_invariants[self.iaddr]
        else:
            return []

    @property
    def is_unresolved(self) -> bool:
        if self.is_call_instruction:
            return not self.xdata.has_call_target()
        elif self.mnemonic == "BX":
            return str(self.xdata.xprs[0]) != "LR"
        return False

    @property
    def is_subsumed(self) -> bool:
        return self.xdata.instruction_is_subsumed()

    @property
    def subsumes(self) -> bool:
        return self.xdata.instruction_subsumes()

    def subsumed_by(self) -> str:
        if self.is_subsumed:
            return self.xdata.subsumed_by()
        else:
            raise UF.CHBError("ARM instruction is not subsumed")

    def return_expr(self) -> XXpr:
        raise UF.CHBError("get-return-expr: not implemented")

    @property
    def ft_conditions(self) -> Sequence[XXpr]:
        if self.is_branch_instruction:
            if self.opcode.tags[0].startswith("IT"):
                opc_it = cast(ARMIfThen, self.opcode)
                return opc_it.ft_conditions(self.xdata)
            else:
                opc = cast(ARMBranch, self.opcode)
                return opc.ft_conditions(self.xdata)
        else:
            return []

    @property
    def annotation(self) -> str:
        if self.is_subsumed:
            aggaddr = self.xdata.subsumed_by()
            return f"subsumed by {aggaddr}"
        elif self.subsumes:
            ann = self.opcode.annotation(self.xdata)
            dependents = self.xdata.subsumes()
            return ann + " (subsumes [" + ", ".join(dependents) + "])"
        else:
            return self.opcode.annotation(self.xdata)

    def has_instruction_condition(self) -> bool:
        return self.xdata.has_instruction_condition()

    def has_condition_block_condition(self) -> bool:
        return self.xdata.has_condition_block_condition()

    def get_instruction_condition(self) -> XXpr:
        return self.xdata.get_instruction_condition()

    @property
    def memory_accesses(self) -> Sequence[MemoryAccess]:
        return self.opcode.memory_accesses(self.xdata)

    def assembly_ast(self, astree: ASTInterface) -> List[ASTInstruction]:
        return self.opcode.assembly_ast(
            astree, self.iaddr, self.bytestring, self.xdata)

    def assembly_ast_condition(
            self, astree: ASTInterface, reverse: bool = False) -> Optional[ASTExpr]:
        return self.opcode.assembly_ast_condition(
            astree, self.iaddr, self.bytestring, self.xdata, reverse)

    def ast(self, astree: ASTInterface) -> List[ASTInstruction]:
        return self.opcode.ast(
            astree, self.iaddr, self.bytestring, self.xdata)

    def ast_prov(self, astree: ASTInterface) -> Tuple[
            List[ASTInstruction], List[ASTInstruction]]:
        """Return instruction ast with provenance."""

        if self.is_subsumed:
            return ([], [])
        else:
            return self.opcode.ast_prov(
                astree, self.iaddr, self.bytestring, self.xdata)

    def is_condition_true(self) -> bool:
        return self.opcode.is_condition_true(self.xdata)

    def ast_condition(
            self, astree: ASTInterface, reverse: bool = False
    ) -> Optional[ASTExpr]:
        return self.opcode.ast_condition(
            astree, self.iaddr, self.bytestring, self.xdata, reverse)

    def ast_condition_prov(
            self, astree: ASTInterface, reverse: bool = False) -> Tuple[
                Optional[ASTExpr], Optional[ASTExpr]]:
        """Return conditional branch instruction with provenance."""

        try:
            return self.opcode.ast_condition_prov(
                astree, self.iaddr, self.bytestring, self.xdata, reverse)
        except Exception as e:
            chklogger.logger.warning(
                "Error in generating condition at address %s: %s. Returning 0.",
                self.iaddr, str(e))
            expr = astree.mk_integer_constant(0)
            return (expr, expr)

    def ast_cc_condition_prov(
            self, astree: ASTInterface
    ) -> Tuple[Optional[ASTExpr], Optional[ASTExpr]]:

        try:
            return self.opcode.ast_cc_condition_prov(
                astree, self.iaddr, self.bytestring, self.xdata)
        except Exception as e:
            chklogger.logger.warning(
                "Error in generating cc-condition at address %s: %s.",
                self.iaddr, str(e))
            expr = astree.mk_temp_lval_expression()
            return (expr, expr)

    def ast_switch_condition_prov(self, astree: ASTInterface) -> Tuple[
            Optional[ASTExpr], Optional[ASTExpr]]:

        if self.xdata.is_aggregate_jumptable:
            jumptable = cast(
                "ARMJumpTable", self.armfunction.get_jumptable(self.iaddr))
            indexop = jumptable.index_operand
            if self.xdata.is_cxpr_ok(0):
                condition = self.xdata.cxprs_r[0]
            else:
                condition = self.xdata.xprs_r[1]
            if condition is not None:
                (ll_cond, _, _) = indexop.ast_rvalue(astree)
                hl_cond = XU.xxpr_to_ast_def_expr(
                    condition, self.xdata, self.iaddr, astree)

                astree.add_expr_mapping(hl_cond, ll_cond)
                astree.add_expr_reachingdefs(hl_cond, self.xdata.reachingdefs)
                astree.add_condition_address(
                    ll_cond, (self.xdata.subsumes() + [self.iaddr]))

                return (hl_cond, ll_cond)
            else:
                chklogger.logger.error(
                    "Error value encountered at address %s", self.iaddr)
                raise UF.CHBError("Jumptable without condition")

        else:
            return self.opcode.ast_switch_condition_prov(
                astree, self.iaddr, self.bytestring, self.xdata)

    @property
    def stackpointer_offset(self) -> StackPointerOffset:
        return self.armfunctiondictionary.read_xml_sp_offset(self.xnode)

    @property
    def strings_referenced(self) -> Sequence[str]:
        return []

    def global_refs(self) -> Tuple[Sequence[XVariable], Sequence[XXpr]]:
        """Return a pair of lhs, rhs global references"."""

        lhs = self.opcode.lhs(self.xdata)
        rhs = self.opcode.rhs(self.xdata)
        return (
            [x for x in lhs if x.is_global_variable],
            [x for x in rhs if x.has_global_references() or x.is_global_address])

    def string_pointer_loaded(self) -> Optional[Tuple[str, str]]:
        return None

    @property
    def call_target(self) -> CallTarget:
        if self.is_call_instruction:
            return self.opcode.call_target(self.xdata)
        else:
            raise UF.CHBError("Not a call instruction: " + str(self))

    @property
    def jump_target(self) -> Optional["XXpr"]:
        return self.opcode.jump_target(self.xdata)

    @property
    def call_arguments(self) -> Sequence[XXpr]:
        if self.is_call_instruction and self.has_call_target():
            return self.opcode.arguments(self.xdata)
        else:
            return []

    def lhs_variables(
            self, filter: Callable[[XVariable], bool]) -> List[XVariable]:
        return [v for v in self.opcode.lhs(self.xdata) if filter(v)]

    def rhs_expressions(self, filter: Callable[[XXpr], bool]) -> List[XXpr]:
        return [x for x in self.opcode.rhs(self.xdata) if filter(x)]

    def rdef_locations(self) -> Dict[str, List[List[str]]]:
        result: Dict[str, Dict[str, List[str]]] = {}

        for rdef in self.xdata.reachingdefs:
            if rdef is not None:
                rdefvar = str(rdef.vardefuse.variable)
                rdeflocs = [str(s) for s in rdef.valid_deflocations]
                result.setdefault(rdefvar, {})
                for sx in rdeflocs:
                    result[rdefvar].setdefault(sx, [])
                    for sy in rdeflocs:
                        if sy not in result[rdefvar][sx]:
                            result[rdefvar][sx].append(sy)
        return {x:list(r.values()) for (x, r) in result.items()}

    def lhs_types(self) -> Dict[str, "BCTyp"]:
        result: Dict[str, "BCTyp"] = {}

        vars = self.xdata.vars_r
        types = self.xdata.types
        if len(vars) == len(types):
            for (v, ty) in zip(vars, types):
                if not ty.is_unknown:
                    result[str(v)] = ty
        else:
            chklogger.logger.warning(
                "Number of variables and types is not the same: %d vs %d "
                + "for instruction at address %s",
                len(vars), len(types), self.iaddr)

        return result

    def to_string(
            self,
            bytes: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 40,
            typingrules: bool = False,
            sp: bool = False) -> str:

        lines: List[str] = []
        if typingrules:
            rulesapplied = self.app.type_constraints.rules_applied_to_instruction(
                self.armfunction.faddr, self.iaddr)
            for r in sorted(str(r) for r in rulesapplied):
                lines.append("   " + str(r))
        try:
            pbytes = self.bytestring.ljust(10) + "  " if bytes else ""
            pesp = str(self.stackpointer_offset) + "  " if sp else ""
            popcode = (
                self.opcodetext.ljust(opcodewidth) if opcodetxt else "")
            codeline = pesp + pbytes + popcode + self.annotation
            if len(lines) > 0:
                return codeline + "\n  " + "\n  ".join(lines)
            else:
                return codeline
        except Exception as e:
            print(
                "Error in instruction: "
                + self.iaddr
                + ": "
                + self.opcodetext
                + ": "
                + str(e))
            raise
            # return "??"

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["addr"] = [self.real_iaddr]
        spresult = self.stackpointer_offset.to_json_result()
        if spresult.is_ok:
            content["stackpointer"] = spresult.content
        content["bytes"] = self.bytestring
        if self.mnemonic.startswith("unknown"):
            reason = (
                "Instruction opcode not recognized at address "
                + self.real_iaddr
                + " (bytes: "
                + self.bytestring
                + ")")
            return JSONResult("assemblyinstruction", {}, "fail", reason)
        try:
            content["opcode"] = [self.mnemonic, self.operandstring]
            content["annotation"] = self.annotation
            return JSONResult("assemblyinstruction", content, "ok")
        except UF.CHBError as e:
            return JSONResult("assemblyinstruction", content, "fail", str(e))
