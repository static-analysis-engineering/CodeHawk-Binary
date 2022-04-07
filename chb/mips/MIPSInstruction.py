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
"""MIPS function basic block."""

import xml.etree.ElementTree as ET

from typing import (
    Any, cast, Dict, List, Mapping, Optional, Sequence, Tuple, TYPE_CHECKING)

from chb.api.CallTarget import CallTarget

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree
from chb.app.ASTNode import ASTNode, ASTInstruction, ASTExpr

from chb.app.FunctionDictionary import FunctionDictionary
from chb.app.Instruction import Instruction
from chb.app.InstrXData import InstrXData
from chb.app.StackPointerOffset import StackPointerOffset

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

from chb.mips.MIPSOpcode import MIPSOpcode
from chb.mips.MIPSOperand import MIPSOperand

from chb.mips.opcodes.MIPSBranchOpcode import MIPSBranchOpcode
from chb.mips.opcodes.MIPSJumpLinkRegister import MIPSJumpLinkRegister

import chb.util.IndexedTable as IT
import chb.simulation.SimUtil as SU
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.mips.MIPSBlock import MIPSBlock
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.mips.MIPSFunction import MIPSFunction
    from chb.mips.opcodes.MIPSLoadWord import MIPSLoadWord
    from chb.simulation.SimulationState import SimulationState


class MIPSInstruction(Instruction):

    def __init__(
            self,
            mipsblock: "MIPSBlock",
            xnode: ET.Element) -> None:
        Instruction.__init__(self, xnode)
        self._mipsblock = mipsblock
        self._opcode: Optional[MIPSOpcode] = None
        self._opcodetext: Optional[str] = None
        self._xdata: Optional[InstrXData] = None

    @property
    def block(self) -> "MIPSBlock":
        return self._mipsblock

    @property
    def dictionary(self) -> "MIPSDictionary":
        return self.block.dictionary

    @property
    def functiondictionary(self) -> FunctionDictionary:
        return self.block.functiondictionary

    @property
    def function(self) -> "MIPSFunction":
        return self.block.function

    @property
    def opcode(self) -> MIPSOpcode:
        if self._opcode is None:
            self._opcode = self.dictionary.read_xml_mips_opcode(self.xnode)
        return self._opcode

    @property
    def xdata(self) -> InstrXData:
        if self._xdata is None:
            self._xdata = self.functiondictionary.read_xml_instrx(self.xnode)
        return self._xdata

    @property
    def mnemonic(self) -> str:
        return self.opcode.mnemonic

    @property
    def opcodetext(self) -> str:
        try:
            mnemonic = self.mnemonic
            operands = self.operands
            return mnemonic.ljust(8) + ','.join([str(op) for op in operands])
        except IT.IndexedTableError as e:
            opcode = self.dictionary.read_xml_mips_opcode(self.xnode)
            raise UF.CHBError('Error for MIPS opcode ' + str(opcode) + ': '
                              + str(e))

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        return self.opcode.operands

    @property
    def bytestring(self) -> str:
        return self.dictionary.read_xml_mips_bytestring(self.xnode)

    @property
    def stackpointer_offset(self) -> StackPointerOffset:
        return self.functiondictionary.read_xml_sp_offset(self.xnode)

    @property
    def annotation(self) -> str:
        return self.opcode.annotation(self.xdata)

    def operand_values(self) -> Sequence[XXpr]:
        return self.opcode.operand_values(self.xdata)

    def assembly_ast(self, astree: AbstractSyntaxTree) -> List[ASTInstruction]:
        astree.set_current_addr(self.iaddr)
        return self.opcode.assembly_ast(
            astree, self.iaddr, self.bytestring, self.xdata)

    def assembly_ast_condition(
            self,
            astree: AbstractSyntaxTree,
            reverse: bool = False) -> Optional[ASTExpr]:
        return self.opcode.assembly_ast_condition(
            astree, self.iaddr, self.bytestring, self.xdata)

    def ast(self, astree: AbstractSyntaxTree) -> List[ASTInstruction]:
        astree.set_current_addr(self.iaddr)
        return self.opcode.ast(
            astree, self.iaddr, self.bytestring, self.xdata)

    def ast_condition(
            self,
            astree: AbstractSyntaxTree,
            reverse: bool = False) -> Optional[ASTExpr]:
        return self.opcode.ast_condition(
            astree, self.iaddr, self.bytestring, self.xdata)

    @property
    def strings_referenced(self) -> Sequence[str]:
        return self.opcode.strings(self.xdata)

    def string_pointer_loaded(self) -> Optional[Tuple[str, str]]:
        return self.opcode.string_pointer_loaded(self.xdata)

    def load_address(self) -> XXpr:
        if self.is_load_word_instruction:
            opc = cast("MIPSLoadWord", self.opcode)
            return opc.load_address(self.xdata)
        else:
            raise UF.CHBError("Load address not implemented for " + str(self))

    def global_refs(self) -> Tuple[Sequence[XVariable], Sequence[XXpr]]:
        """Return a pair of lhs, rhs global references."""

        lhs = self.opcode.lhs(self.xdata)
        rhs = self.opcode.rhs(self.xdata)
        return ([x for x in lhs if x.is_structured_var or x.is_global_value],
                [x for x in rhs if x.is_structured_expr])

    def global_variables(self) -> Mapping[str, int]:
        """Return a mapping of global variables referenced to count."""
        return self.opcode.global_variables(self.xdata)

    def registers(self) -> Mapping[str, str]:
        return self.opcode.registers()

    def refers_to_register(self, registers: List[str]) -> bool:
        return any([reg for reg in registers if reg in self.registers()])

    @property
    def is_return_instruction(self) -> bool:
        return self.opcode.is_return_instruction

    @property
    def is_call_instruction(self) -> bool:
        return self.opcode.is_call_instruction(self.xdata)

    @property
    def is_load_instruction(self) -> bool:
        return False

    @property
    def is_store_instruction(self) -> bool:
        return False

    @property
    def is_load_word_instruction(self) -> bool:
        return self.opcode.is_load_word

    @property
    def is_store_word_instruction(self) -> bool:
        return self.opcode.is_store_word

    @property
    def is_restore_register_instruction(self) -> bool:
        return self.opcode.is_restore_register

    def return_value(self) -> Optional[XXpr]:
        if self.is_return_instruction:
            return self.opcode.return_value(self.xdata)
        else:
            raise UF.CHBError(
                "Instruction is not a return instruction: " + str(self))

    def is_call_to_app_function(self, tgtaddr: str) -> bool:
        if self.is_call_instruction:
            opc = cast(MIPSJumpLinkRegister, self.opcode)
            ctgtaddr = opc.call_target(self.xdata)
            return ctgtaddr == tgtaddr
        return False

    def call_facts(self) -> Mapping[str, Any]:
        if not self.is_call_instruction:
            raise UF.CHBError("Not a call instruction: " + str(self))
        result: Dict[str, Any] = {}
        callargs = self.annotated_call_arguments()
        if callargs:
            result['args'] = callargs
        tgt = self.call_target
        if tgt == 'call-target:u':
            result['t'] = '?'
        else:
            result['t'] = str(tgt)
        return result

    def annotated_call_arguments(self) -> List[Dict[str, Any]]:
        if self.is_call_instruction:
            opc = cast(MIPSJumpLinkRegister, self.opcode)
            return opc.annotated_call_arguments(self.xdata)
        else:
            raise UF.CHBError("Not a call instruction: " + str(self))

    @property
    def call_target(self) -> CallTarget:
        if self.is_call_instruction:
            opc = cast(MIPSJumpLinkRegister, self.opcode)
            return opc.call_target(self.xdata)
        else:
            raise UF.CHBError("Not a call instruction: " + str(self))

    @property
    def call_arguments(self) -> Sequence[XXpr]:
        if self.is_call_instruction:
            opc = cast(MIPSJumpLinkRegister, self.opcode)
            return opc.arguments(self.xdata)
        else:
            raise UF.CHBError("Not a call instruction: " + str(self))

    def has_string_arguments(self) -> bool:
        if self.is_call_instruction:
            opc = cast(MIPSJumpLinkRegister, self.opcode)
            return opc.has_string_arguments(self.xdata)
        else:
            return False

    def has_stack_arguments(self) -> bool:
        if self.is_call_instruction:
            opc = cast(MIPSJumpLinkRegister, self.opcode)
            return opc.has_stack_arguments(self.xdata)
        else:
            return False

    @property
    def is_branch_instruction(self) -> bool:
        return self.opcode.is_branch_instruction

    def has_branch_condition(self) -> bool:
        return False

    def branch_condition(self) -> XXpr:
        if self.has_branch_condition():
            opc = cast(MIPSBranchOpcode, self.opcode)
            return cast(XXpr, opc.branch_condition(self.xdata))
        else:
            raise UF.CHBError("Instruction does not have a branch condition")

    @property
    def is_memory_assign(self) -> bool:
        if self.mnemonic == 'sw':
            xdata = self.xdata
            if len(xdata.xprs) >= 3:
                lhs = xdata.vars[0]
                return (lhs.has_denotation
                        and lhs.denotation.is_memory_variable)
        return False

    def memory_assign(self) -> Tuple[XVariable, XXpr]:
        if self.is_memory_assign:
            lhs = self.xdata.vars[0]
            rhs = self.xdata.xprs[1]
            return (lhs, rhs)
        else:
            raise UF.CHBError('Instruction is not a memory assign')

    @property
    def rhs(self) -> Sequence[XXpr]:
        return self.opcode.rhs(self.xdata)

    @property
    def lhs(self) -> Sequence[XVariable]:
        return self.opcode.lhs(self.xdata)

    @property
    def ft_conditions(self) -> Sequence[XXpr]:
        """Return false, true condition."""

        if self.is_branch_instruction:
            opc = cast(MIPSBranchOpcode, self.opcode)
            return opc.ft_conditions(self.xdata)
        return []

    def simulate(self, simstate: "SimulationState") -> None:
        try:
            self.opcode.simulate(self.iaddr, simstate)
        except SU.CHBSimError as e:
            e.instrtxt = self.to_string()
            raise e

    def to_string(
            self,
            bytes: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 25,
            sp: bool = True) -> str:
        pbytes = self.bytestring + "  " if bytes else ""
        pesp = str(self.stackpointer_offset) + '  ' if sp else ''
        popcode = self.opcodetext.ljust(opcodewidth) if opcodetxt else ''
        return pesp + pbytes + popcode + self.annotation

    def __str__(self) -> str:
        return self.to_string()
