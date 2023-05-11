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
"""ARM opcodes."""

from typing import List, Optional, Sequence, Tuple, TYPE_CHECKING

from chb.api.CallTarget import CallTarget

from chb.app.InstrXData import InstrXData
from chb.app.MemoryAccess import MemoryAccess

from chb.arm.ARMDictionaryRecord import ARMDictionaryRecord
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.VarInvariantFact import DefUse, DefUseHigh, ReachingDefFact
from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

import chb.simulation.SimUtil as SU
import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.simulation.SimulationState import SimulationState


def simplify_result(id1: int, id2: int, x1: XXpr, x2: XXpr) -> str:
    if id1 == id2:
        return str(x1)
    else:
        return str(x1) + ' (= ' + str(x2) + ')'


branch_opcodes = [
    "B", "BX"
]

call_opcodes = [
    "BLX", "BL"
]


extensions = {
    "eq": "EQ",
    "ne": "NE",
    "cs": "CS",
    "cc": "CC",
    "neg": "MI",
    "nneg": "PL",
    "ov": "VS",
    "nov": "VC",
    "uh": "HI",
    "nuh": "LS",
    "ge": "GE",
    "lt": "LT",
    "gt": "GT",
    "le": "LE",
    "a": "",
    "unc": ""
    }


def get_extension(e: str) -> str:
    if e in extensions:
        return extensions[e]
    else:
        return e


class ARMOpcode(ARMDictionaryRecord):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMDictionaryRecord.__init__(self, d, ixval)

    @property
    def mnemonic(self) -> str:
        return self.tags[0]

    def annotation(self, xdata: InstrXData) -> str:
        return self.__str__()

    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        msg = (
            iaddr + ": "
            + bytestring
            + "  "
            + self.mnemonic
            + " "
            + self.operandstring
            + ": "
            + self.annotation(xdata))
        astree.add_instruction_unsupported(self.mnemonic, msg)
        return []

    def assembly_ast_condition(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData,
            reverse: bool) -> Optional[AST.ASTExpr]:
        msg = (
            bytestring
            + "  "
            + self.mnemonic
            + " "
            + self.operandstring
            + ": "
            + self.annotation(xdata))
        raise UF.CHBError("No assembly-ast-condition defined for " + msg)

    def ast(self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        return self.assembly_ast(astree, iaddr, bytestring, xdata)

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        """Return default; should be overridden by instruction opcodes."""

        instrs = self.ast(astree, iaddr, bytestring, xdata)
        return (instrs, instrs)

    def is_condition_true(self, xdata: InstrXData) -> bool:
        return False

    def ast_condition(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData,
            reverse: bool) -> Optional[AST.ASTExpr]:
        return self.assembly_ast_condition(
            astree, iaddr, bytestring, xdata, reverse)

    def ast_condition_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData,
            reverse: bool) -> Tuple[Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:
        """ Return default; should be overridden by instruction opcodes."""

        expr = self.ast_condition(astree, iaddr, bytestring, xdata, reverse)
        return (expr, expr)

    def ast_switch_condition_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:
        """ Return default; should be overridden by instruction opcodes."""

        return (None, None)

    def ast_variable_intro(
            self,
            astree: ASTInterface,
            ctype: Optional[AST.ASTTyp],
            hl_lhs: AST.ASTLval,
            hl_rhs: AST.ASTExpr,
            ll_lhs: AST.ASTLval,
            ll_rhs: AST.ASTExpr,
            hl_rdefs: List[Optional[ReachingDefFact]],
            ll_rdefs: List[Optional[ReachingDefFact]],
            defuses: Optional[DefUse],
            defuseshigh: Optional[DefUseHigh],
            addregdef: bool,
            iaddr: str,
            annotations: List[str],
            bytestring: str) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        hl_assigns: List[AST.ASTInstruction] = []
        if astree.has_variable_intro(iaddr):
            vname = astree.get_variable_intro(iaddr)
            vinfo = astree.mk_vinfo(vname, vtype=ctype, vdescr="intro")
            vinfolval = astree.mk_vinfo_lval(vinfo)
            vinfolvalexpr = astree.mk_lval_expr(vinfolval)

            annotations = annotations + ["lhs-intro"]

            hl_intro_assign = astree.mk_assign(
                vinfolval,
                hl_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)

            hl_assign = astree.mk_assign(
                hl_lhs,
                vinfolvalexpr,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)

            if addregdef:
                astree.add_reg_definition(iaddr, hl_lhs, hl_rhs)
            else:
                astree.add_reg_definition(iaddr, hl_lhs, vinfolvalexpr)
            astree.add_instr_mapping(hl_intro_assign, ll_assign)
            astree.add_instr_address(hl_intro_assign, [iaddr])
            astree.add_expr_mapping(vinfolvalexpr, ll_rhs)
            astree.add_lval_mapping(vinfolval, ll_lhs)
            astree.add_lval_defuses(vinfolval, defuses)
            astree.add_lval_defuses_high(vinfolval, defuseshigh)

            hl_assigns = [hl_intro_assign, hl_assign]

        else:
            hl_assign = astree.mk_assign(
                hl_lhs,
                hl_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)

            if addregdef:
                astree.add_reg_definition(iaddr, hl_lhs, hl_rhs)

            hl_assigns = [hl_assign]

        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(hl_rhs, hl_rdefs)
        astree.add_expr_reachingdefs(ll_rhs, ll_rdefs)
        astree.add_lval_defuses(hl_lhs, defuses)
        astree.add_lval_defuses_high(hl_lhs, defuseshigh)

        return (hl_assigns, [ll_assign])

    def ast_cc_expr(self, astree: ASTInterface) -> AST.ASTExpr:
        cc = self.mnemonic_extension()

        def zflag() -> AST.ASTLvalExpr:
            return astree.mk_flag_variable_lval_expression("Z")

        def cflag() -> AST.ASTLvalExpr:
            return astree.mk_flag_variable_lval_expression("C")

        def vflag() -> AST.ASTLvalExpr:
            return astree.mk_flag_variable_lval_expression("V")

        def nflag() -> AST.ASTLvalExpr:
            return astree.mk_flag_variable_lval_expression("N")

        def one() -> AST.ASTIntegerConstant:
            return astree.mk_integer_constant(1)

        def zero() -> AST.ASTIntegerConstant:
            return astree.mk_integer_constant(0)

        def flagexpr(op: str, x: AST.ASTExpr, v: AST.ASTExpr) -> AST.ASTExpr:
            return astree.mk_binary_expression(op, x, v)

        if cc == "EQ":
            return flagexpr("eq", zflag(), one())
        elif cc == "NE":
            return flagexpr("eq", zflag(), zero())
        elif cc == "CS":
            return flagexpr("eq", cflag(), one())
        elif cc == "CC":
            return flagexpr("eq", cflag(), zero())
        elif cc == "MI":
            return flagexpr("eq", nflag(), one())
        elif cc == "PL":
            return flagexpr("eq", nflag(), zero())
        elif cc == "VS":
            return flagexpr("eq", vflag(), one())
        elif cc == "VC":
            return flagexpr("eq", vflag(), zero())
        elif cc == "HI":
            e1 = flagexpr("eq", cflag(), one())
            e2 = flagexpr("eq", zflag(), zero())
            return flagexpr("and", e1, e2)
        elif cc == "LS":
            e1 = flagexpr("eq", cflag(), zero())
            e2 = flagexpr("eq", zflag(), one())
            return flagexpr("lor", e1, e2)
        elif cc == "GE":
            return flagexpr("eq", nflag(), vflag())
        elif cc == "LT":
            return flagexpr("ne", nflag(), vflag())
        elif cc == "GT":
            e1 = flagexpr("eq", zflag(), zero())
            e2 = flagexpr("eq", nflag(), vflag())
            return flagexpr("eq", e1, e2)
        elif cc == "LE":
            e1 = flagexpr("eq", zflag(), one())
            e2 = flagexpr("ne", nflag(), vflag())
            return flagexpr("lor", e1, e2)
        elif cc == "":
            return one()
        else:
            return zero()

    def mnemonic_extension(self) -> str:
        if self.mnemonic.startswith("IT"):
            return ""
        elif len(self.tags) > 1:
            return get_extension(self.tags[1])
        else:
            return ""

    @property
    def operands(self) -> List[ARMOperand]:
        """Return the operands that appear in the printed assembly instruction.

        Note that this is often a subset of the operands present.
        """

        return []

    @property
    def opargs(self) -> List[ARMOperand]:
        """Return all operand types in the assembly instruction arguments.

        This excludes items in the operand list that are integers or booleans.
        """

        return []

    @property
    def operandstring(self) -> str:
        return ", ".join(str(op) for op in self.operands)

    def memory_accesses(self, xdata: InstrXData) -> Sequence[MemoryAccess]:
        return []

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        """Return lhs variables."""
        return xdata.vars

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        """Return rhs expressions."""
        return xdata.xprs

    def is_stack_access(self, xdata: InstrXData) -> bool:
        return False

    @property
    def is_branch_instruction(self) -> bool:
        return (self.tags[0] in branch_opcodes) or self.tags[0].startswith("IT")

    def is_return_instruction(self, xdata: InstrXData) -> bool:
        return False

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        return self.mnemonic in call_opcodes or xdata.has_call_target()

    def call_target(self, xdata: InstrXData) -> CallTarget:
        raise UF.CHBError("Instruction is not a call: " + str(self))

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        raise UF.CHBError("Instruction is not a call: " + str(self))

    def is_load_instruction(self, xdata: InstrXData) -> bool:
        return False

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return False

    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        raise SU.CHBSimError(
            simstate,
            iaddr,
            ("Simulation not yet supported for "
             + str(self)
             + " at address "
             + str(iaddr)))

    def __str__(self) -> str:
        return self.tags[0] + ":pending"
