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

import xml.etree.ElementTree as ET

from typing import (
    Callable, cast, Dict, List, Optional, Sequence, Tuple, TYPE_CHECKING)

from chb.api.CallTarget import CallTarget

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree
from chb.app.ASTNode import ASTNode, ASTInstruction, ASTExpr
from chb.app.FunctionDictionary import FunctionDictionary
from chb.app.Instruction import Instruction
from chb.app.InstrXData import InstrXData
from chb.app.Operand import Operand
from chb.app.StackPointerOffset import StackPointerOffset

from chb.arm.ARMDictionary import ARMDictionary
from chb.arm.ARMOpcode import ARMOpcode
from chb.arm.ARMOperand import ARMOperand
from chb.arm.opcodes.ARMBranch import ARMBranch

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.arm.ARMBlock import ARMBlock
    from chb.arm.ARMFunction import ARMFunction


class ARMInstruction(Instruction):

    def __init__(
            self,
            armblock: "ARMBlock",
            xnode: ET.Element) -> None:
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
    def armfunctiondictionary(self) -> "FunctionDictionary":
        return self.armfunction.armfunctiondictionary

    @property
    def opcode(self) -> ARMOpcode:
        if self._opcode is None:
            self._opcode = self.armdictionary.read_xml_arm_opcode(self.xnode)
        return self._opcode

    @property
    def xdata(self) -> InstrXData:
        if self._xdata is None:
            self._xdata = self.armfunctiondictionary.read_xml_instrx(self.xnode)
        return self._xdata

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
            return self.mnemonic.ljust(15) + self.operandstring
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
        return self.opcode.is_branch_instruction

    def return_expr(self) -> XXpr:
        raise UF.CHBError("get-return-expr: not implemented")

    @property
    def ft_conditions(self) -> Sequence[XXpr]:
        if self.is_branch_instruction:
            opc = cast(ARMBranch, self.opcode)
            return opc.ft_conditions(self.xdata)
        else:
            return []

    @property
    def annotation(self) -> str:
        return self.opcode.annotation(self.xdata).ljust(40)

    def assembly_ast(self, astree: AbstractSyntaxTree) -> List[ASTInstruction]:
        astree.set_current_addr(self.iaddr)
        return self.opcode.assembly_ast(
            astree, self.iaddr, self.bytestring, self.xdata)

    def assembly_ast_condition(self, astree: AbstractSyntaxTree) -> Optional[ASTExpr]:
        return self.opcode.assembly_ast_condition(
            astree, self.iaddr, self.bytestring, self.xdata)

    def ast(self, astree: AbstractSyntaxTree) -> List[ASTInstruction]:
        astree.set_current_addr(self.iaddr)
        return self.opcode.ast(
            astree, self.iaddr, self.bytestring, self.xdata)

    def ast_condition(self, astree: AbstractSyntaxTree) -> Optional[ASTExpr]:
        return self.opcode.ast_condition(
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
            [x for x in rhs if x.has_global_references()])

    def string_pointer_loaded(self) -> Optional[Tuple[str, str]]:
        return None

    @property
    def call_target(self) -> CallTarget:
        if self.is_call_instruction:
            return self.opcode.call_target(self.xdata)
        else:
            raise UF.CHBError("Not a call instruction: " + str(self))

    @property
    def call_arguments(self) -> Sequence[XXpr]:
        return []

    def to_string(
            self,
            bytes: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 40,
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
                + self.opcodetext
                + ": "
                + str(e))
            return "??"
