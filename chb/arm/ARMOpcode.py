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
"""ARM opcodes."""

import inspect

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
import chb.invariants.XXprUtil as XU

import chb.simulation.SimUtil as SU
import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr
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


class ARMOpcodeXData:

    def __init__(self, xdata: InstrXData) -> None:
        self._xdata = xdata

    @property
    def xdata(self) -> InstrXData:
        return self._xdata

    @property
    def is_ok(self) -> bool:
        return self.xdata.is_ok

    def var(self, index: int, name: str) -> "XVariable":
        if not self.has_var(index):
            raise UF.CHBError(
                self.__class__.__name__ + ":"
                + name + " index out of bounds: " + str(index))
        v = self.xdata.vars_r[index]
        if v is None:
            raise UF.CHBError(
                self.__class__.__name__ + ":" + name + " has an error value")
        return v

    def has_var(self, index: int) -> bool:
        return self.xdata.has_var_r(index)

    def is_var_ok(self, index: int) -> bool:
        return self.xdata.is_var_ok(index)

    def cvar(self, index: int, name: str) -> "XVariable":
        if not self.has_cvar(index):
            raise UF.CHBError(
                self.__class__.__name__ + ":"
                + name + " index out of bounds: " + str(index))
        cv = self.xdata.cvars_r[index]
        if cv is None:
            raise UF.CHBError(
                self.__class__.__name__ + ":" + name + " has an error value")
        return cv

    def has_cvar(self, index: int) -> bool:
        return self.xdata.has_cxpr_r(index)

    def is_cvar_ok(self, index: int) -> bool:
        return self.xdata.is_cvar_ok(index)

    def xpr(self, index: int, name: str) -> "XXpr":
        if not self.has_xpr(index):
            raise UF.CHBError(
                self.__class__.__name__ + ":"
                + name + " index out of bounds: " + str(index))
        x = self.xdata.xprs_r[index]
        if x is None:
            raise UF.CHBError(
                self.__class__.__name__ + ":" + name + " has an error value")
        return x

    def has_xpr(self, index: int) -> bool:
        return self.xdata.has_xpr_r(index)

    def is_xpr_ok(self, index: int) -> bool:
        return self.xdata.is_xpr_ok(index)

    def cxpr(self, index: int, name: str) -> "XXpr":
        if index >= len(self.xdata.cxprs_r):
            raise UF.CHBError(
                self.__class__.__name__ + ":"
                + name + " cxpr index out of bounds: " + str(index))
        cx = self.xdata.cxprs_r[index]
        if cx is None:
            raise UF.CHBError(
                self.__class__.__name__ + ":" + name + " has an error value")
        return cx

    def has_cxpr(self, index: int) -> bool:
        return self.xdata.has_cxpr_r(index)

    def is_cxpr_ok(self, index: int) -> bool:
        return self.xdata.is_cxpr_ok(index)

    def has_instruction_condition(self) -> bool:
        return self.xdata.has_instruction_condition()

    def get_instruction_condition(self) -> "XXpr":
        return self.xdata.get_instruction_condition()

    def has_valid_instruction_c_condition(self) -> bool:
        return self.xdata.has_valid_instruction_c_condition()

    def get_instruction_c_condition(self) -> "XXpr":
        return self.xdata.get_instruction_c_condition()

    def add_instruction_condition(self, s: str) -> str:
        if self.xdata.has_unknown_instruction_condition():
            return "if ? then " + s
        if self.has_valid_instruction_c_condition():
            ccond = "(C: " + str(self.get_instruction_c_condition()) + ")"
        else:
            ccond = "(C: none)"
        if self.xdata.has_instruction_condition():
            c = str(self.xdata.get_instruction_condition()) + ccond
            return "if " + c + " then " + s
        else:
            return s

    @property
    def is_writeback(self) -> bool:
        return self.xdata.has_base_update()

    def get_base_update_var(self) -> "XVariable":
        if self.is_writeback:
            return self.xdata.get_base_update_var()
        else:
            raise UF.CHBError(
                self.__class__.__name__ + " does not have writeback")

    def get_base_update_xpr(self) -> "XXpr":
        if self.is_writeback:
            return self.xdata.get_base_update_xpr()
        else:
            raise UF.CHBError(
                self.__class__.__name__ + " does not have writeback")

    def get_base_update_cxpr(self) -> "XXpr":
        if self.is_writeback:
            return self.xdata.get_base_update_cxpr()
        else:
            raise UF.CHBError(
                self.__class__.__name__ + " does not have writeback")

    def writeback_update(self) -> str:
        if self.xdata.has_base_update():
            vbu = self.get_base_update_var()
            xbu = self.get_base_update_cxpr()
            return "; wbu: " + str(vbu) + " := " + str(xbu)
        else:
            return ""


class ARMOpcode(ARMDictionaryRecord):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMDictionaryRecord.__init__(self, d, ixval)

    @property
    def mnemonic(self) -> str:
        return self.tags[0]

    @property
    def mnemonic_stem(self) -> str:
        return self.mnemonic

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

        chklogger.logger.error(
            "no lifting support available for instruction %s at address %s",
            self.mnemonic, iaddr)
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

    def ast_cc_condition_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData
    ) -> Tuple[Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:

        ll_astcond = self.ast_cc_expr(astree)

        if xdata.has_instruction_condition():
            xd = ARMOpcodeXData(xdata)
            if xd.has_valid_instruction_c_condition():
                pcond = xd.get_instruction_c_condition()
            else:
                pcond = xd.get_instruction_condition()
            hl_astcond = XU.xxpr_to_ast_def_expr(pcond, xdata, iaddr, astree)

            astree.add_expr_mapping(hl_astcond, ll_astcond)
            astree.add_expr_reachingdefs(hl_astcond, xdata.reachingdefs)
            astree.add_flag_expr_reachingdefs(ll_astcond, xdata.flag_reachingdefs)
            astree.add_condition_address(ll_astcond, [iaddr])

            return (hl_astcond, ll_astcond)

        else:
            chklogger.logger.error(
                "No condition found at address %s", iaddr)
            hl_astcond = astree.mk_temp_lval_expression()
            return (hl_astcond, ll_astcond)

    def ast_switch_condition_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:

        if xdata.is_aggregate_jumptable:
            condition = xdata.xprs[1]
            hl_conds = XU.xxpr_to_ast_def_exprs(condition, xdata, iaddr, astree)
            if len(hl_conds) == 1:
                return (hl_conds[0], None)
            else:
                return (None, None)
        else:
            return (None, None)

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

    def is_conditional_return_instruction(self, xdata: InstrXData) -> bool:
        return False

    def return_value(self, xdata: InstrXData) -> Optional[XXpr]:
        return None

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        return self.mnemonic in call_opcodes or xdata.has_call_target()

    def call_target(self, xdata: InstrXData) -> CallTarget:
        raise UF.CHBError("Instruction is not a call: " + str(self))

    def jump_target(self, xdata: InstrXData) -> Optional["XXpr"]:
        return None

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        raise UF.CHBError("Instruction is not a call: " + str(self))

    def is_load_instruction(self, xdata: InstrXData) -> bool:
        return False

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return False

    def is_nop_instruction(self, xdata: InstrXData) -> bool:
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
