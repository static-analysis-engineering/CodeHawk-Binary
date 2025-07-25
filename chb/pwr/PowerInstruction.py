# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2025  Aarno Labs LLC
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
    Callable, cast, Dict, List, Optional, Sequence, Tuple, TYPE_CHECKING)

from chb.api.CallTarget import CallTarget

from chb.app.FunctionDictionary import FunctionDictionary
from chb.app.Instruction import Instruction
from chb.app.InstrXData import InstrXData
from chb.app.MemoryAccess import MemoryAccess
from chb.app.Operand import Operand
from chb.app.StackPointerOffset import StackPointerOffset

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.InvariantFact import InvariantFact
from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

from chb.pwr.PowerDictionary import PowerDictionary
from chb.pwr.PowerOpcode import PowerOpcode
from chb.pwr.PowerOperand import PowerOperand

if TYPE_CHECKING:
    from chb.pwr.PowerBlock import PowerBlock
    from chb.pwr.PowerFunction import PowerFunction


class PowerInstruction(Instruction):
    def __init__(self, pwrblock: "PowerBlock", xnode: ET.Element) -> None:
        Instruction.__init__(self, xnode)
        self._pwrblock = pwrblock
        self._opcode: Optional[PowerOpcode] = None
        self._opcodetxt: Optional[str] = None
        self._xdata: Optional[InstrXData] =  None

    @property
    def pwrblock(self) -> "PowerBlock":
        return self._pwrblock

    @property
    def pwrfunction(self) -> "PowerFunction":
        return self.pwrblock.pwrfunction

    @property
    def pwrdictionary(self) -> "PowerDictionary":
        return self.pwrblock.pwrdictionary

    @property
    def pwrfunctiondictionary(self) -> "FunctionDictionary":
        return self.pwrfunction.pwrfunctiondictionary

    @property
    def opcode(self) -> PowerOpcode:
        if self._opcode is None:
            self._opcode = self.pwrdictionary.read_xml_pwr_opcode(self.xnode)
        return self._opcode

    @property
    def xdata(self) -> InstrXData:
        if self._xdata is None:
            self._xdata = self.pwrfunctiondictionary.read_xml_instrx(self.xnode)
        return self._xdata

    @property
    def mnemonic(self) -> str:
        return self.opcode.mnemonic

    @property
    def lhs(self) -> Sequence[XVariable]:
        return self.opcode.lhs(self.xdata)

    @property
    def rhs(self) -> Sequence[XXpr]:
        return self.opcode.rhs(self.xdata)

    @property
    def opcodetext(self) -> str:
        try:
            return self.mnemonic.ljust(14) + "  " + self.operandstring
        except IT.IndexedTableError as e:
            opcode = self.pwrdictionary.read_xml_pwr_opcode(self.xnode)
            raise UF.CHBError(
                "Error for Power opcode "
                + str(opcode)
                + " in function "
                + self.pwrfunction.faddr
                + " at address "
                + self.iaddr
                + ": "
                + str(e))

    @property
    def operands(self) -> Sequence[PowerOperand]:
        return self.opcode.operands

    @property
    def operandstring(self) -> str:
        return self.opcode.operandstring

    @property
    def bytestring(self) -> str:
        return self.pwrdictionary.read_xml_pwr_bytestring(self.xnode)

    @property
    def is_call_instruction(self) -> bool:
        return self.opcode.is_call_instruction(self.xdata)

    @property
    def is_jump_instruction(self) -> bool:
        return self.opcode.is_jump_instruction(self.xdata)

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
    def is_branch_instruction(self) -> bool:
        return self.opcode.is_branch_instruction(self.xdata)

    @property
    def is_unresolved(self) -> bool:
        if self.is_call_instruction:
            return not self.xdata.has_call_target()
        return False

    @property
    def annotation(self) -> str:
        return self.opcode.annotation(self.xdata).ljust(40)

    @property
    def memory_accesses(self) -> Sequence[MemoryAccess]:
        return self.opcode.memory_accesses(self.xdata)

    @property
    def invariants(self) -> Sequence[InvariantFact]:
        return []

    @property
    def ft_conditions(self) -> Sequence[XXpr]:
        return []

    @property
    def stackpointer_offset(self) -> StackPointerOffset:
        return self.pwrfunctiondictionary.read_xml_sp_offset(self.xnode)

    @property
    def strings_referenced(self) -> Sequence[str]:
        return []

    def global_refs(self) -> Tuple[Sequence[XVariable], Sequence[XXpr]]:
        """Return a pair of lhs, rhs global references."""

        lhs = self.opcode.lhs(self.xdata)
        rhs = self.opcode.rhs(self.xdata)
        return (
            [x for x in lhs if x.is_global_variable],
            [x for x in rhs if x.has_global_references()])

    def string_pointer_loaded(self) -> Optional[Tuple[str, str]]:
        return None

    def ast_prov(self, astree: ASTInterface) -> Tuple[
            List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return self.opcode.ast_prov(
            astree, self.iaddr, self.bytestring, self.xdata)

    def ast_condition_prov(
            self, astree: ASTInterface, reverse: bool = False) -> Tuple[
                Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:
        """Return conditional branch instruction with provenance."""

        try:
            return self.opcode.ast_condition_prov(
                astree, self.iaddr, self.bytestring, self.xdata, reverse)
        except Exception:
            expr = astree.mk_integer_constant(0)
            return (expr, expr)

    @property
    def call_target(self) -> CallTarget:
        if self.is_call_instruction:
            return self.opcode.call_target(self.xdata)
        else:
            raise UF.CHBError("Not a call instruction: " + str(self))

    @property
    def call_arguments(self) -> Sequence[XXpr]:
        if self.is_call_instruction and self.has_call_target():
            return self.opcode.arguments(self.xdata)
        else:
            return []

    def to_string(
            self,
            bytes: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 40,
            typingrules: bool = False,
            sp: bool = False) -> str:
        try:
            pbytes = self.bytestring.ljust(10) + "  " if bytes else ""
            pesp = str(self.stackpointer_offset) + "  " if sp else ""
            popcode = (
                self.opcodetext.ljust(opcodewidth) if opcodetxt else "")
            return pesp + pbytes + popcode + self.annotation
        except Exception as e:
            print(
                "Error in instruction: "
                + self.iaddr
                + ": "
                + str(e))
            raise
