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
"""Superclass for all Power opcodes."""

from typing import List, Optional, Sequence, Tuple, TYPE_CHECKING

from chb.api.CallTarget import CallTarget

from chb.app.InstrXData import InstrXData
from chb.app.MemoryAccess import MemoryAccess

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.VarInvariantFact import DefUse, DefUseHigh, ReachingDefFact
from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

from chb.pwr.PowerDictionaryRecord import PowerDictionaryRecord
from chb.pwr.PowerOperand import PowerOperand

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.pwr.PowerDictionary import PowerDictionary


branch_opcodes: List[str] = []

call_opcodes: List[str] = []


class PowerOpcode(PowerDictionaryRecord):

    def __init__(
            self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerDictionaryRecord.__init__(self, pwrd, ixval)

    @property
    def mnemonic(self) -> str:
        return self.tags[0]

    def annotation(self, xdata: InstrXData) -> str:
        return self.__str__()

    @property
    def operands(self) -> List[PowerOperand]:
        """Return the operands that appear in the printed assembly instructions.

        Note that this is offten a subset of the operands present.
        """

        return []

    @property
    def opargs(self) -> List[PowerOperand]:
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
        return xdata.vars

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return xdata.xprs

    def is_branch_instruction(self, xdata: InstrXData) -> bool:
        return self.tags[0] in branch_opcodes

    def is_return_instruction(self, xdata: InstrXData) -> bool:
        return False

    def is_jump_instruction(self, xdata: InstrXData) -> bool:
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

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
            List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return ([], [])

    def ast_condition_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData,
            reverse: bool) -> Tuple[
                Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:
        """Return default; should be overridden by instruction opcodes."""

        expr = astree.mk_integer_constant(0)
        return (None, None)

    def ast_variable_intro(
            self,
            astree: ASTInterface,
            iaddr: str,
            annotations: List[str],
            bytestring: str,
            hl_lhs: AST.ASTLval,
            hl_rhs: AST.ASTExpr,
            ll_lhs: AST.ASTLval,
            ll_rhs: AST.ASTExpr,
            hl_rdefs: List[Optional[ReachingDefFact]] = [],
            ll_rdefs: List[Optional[ReachingDefFact]] = [],
            defuses: Optional[DefUse] = None,
            defuseshigh: Optional[DefUseHigh] = None,
            addregdef: bool = True) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        regdef_lhs = hl_lhs

        hl_assigns: List[AST.ASTInstruction] = []

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        if addregdef:
            chklogger.logger.info(
                "Register definition at address %s for %s: %s with %s",
                iaddr,
                str(ll_lhs),
                str(regdef_lhs),
                str(hl_rhs))
            astree.add_reg_definition(iaddr, regdef_lhs, hl_rhs)

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




    def __str__(self) -> str:
        return self.tags[0] + ":pending"
