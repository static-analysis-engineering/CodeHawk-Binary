# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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
#
# ------------------------------------------------------------------------------
"""MIPS assembly code."""

import xml.etree.ElementTree as ET

from typing import cast, Dict, List, Mapping, Optional, TYPE_CHECKING

from chb.app.Assembly import Assembly, AssemblyInstruction
from chb.mips.MIPSOpcode import MIPSOpcode
from chb.mips.MIPSOperand import MIPSOperand

import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.mips.MIPSAccess import MIPSAccess
    from chb.mips.opcodes.MIPSJumpLinkRegister import MIPSJumpLinkRegister
    from chb.simulation.SimulationState import SimulationState


class MIPSAssemblyInstruction(AssemblyInstruction):

    def __init__(
            self,
            iaddr: str,
            opcode: MIPSOpcode,
            stat: str = ""):
        AssemblyInstruction.__init__(self, iaddr, stat)
        self._opcode = opcode

    @property
    def opcode(self) -> MIPSOpcode:
        return self._opcode

    @property
    def mnemonic(self) -> str:
        return self.opcode.mnemonic

    @property
    def is_delay_slot(self) -> bool:
        return 'D' in self._stat

    @property
    def is_block_entry(self) -> bool:
        return "B" in self._stat

    @property
    def is_function_entry(self) -> bool:
        return "F" in self._stat

    @property
    def is_return_instruction(self) -> bool:
        return self.opcode.is_return_instruction

    @property
    def is_call_instruction(self) -> bool:
        return self.opcode.mnemonic == "jalr"

    @property
    def call_operand(self) -> MIPSOperand:
        if self.opcode.mnemonic == "jalr":
            opc = cast("MIPSJumpLinkRegister", self.opcode)
            return opc.tgt_operand
        else:
            raise UF.CHBError("Instruction is not jalr")

    @property
    def operand_count(self) -> int:
        return len(self.opcode.operands)

    def operand(self, i: int) -> MIPSOperand:     # 1-based
        operands = self.opcode.operands
        if len(operands) >= i:
            return operands[i-1]
        else:
            raise UF.CHBError(
                "Instruction "
                + str(self)
                + " does not have "
                + str(i)
                + " operands")

    def lw_stack_offset(self) -> Optional[int]:
        if self.mnemonic == 'lw':
            lwop = self.operand(2)
            if lwop.is_mips_indirect_register_with_reg('sp'):
                return lwop.indirect_register_offset
        return None

    def loads_program_address(self) -> bool:
        return (self.mnemonic == 'lw'
                and self.operand(2).is_mips_indirect_register_with_reg('gp'))

    def loads_stack_value(self) -> bool:
        return (self.mnemonic == 'lw'
                and self.operand(2).is_mips_indirect_register_with_reg('sp'))

    def assigns_stack_address(self) -> bool:
        return (((len(self.opcode.operands) == 3)
                 and not (str(self.operand(1)) == 'sp')
                 and (str(self.operand(2)) == 'sp')
                 and (self.operand(3).is_mips_immediate))
                or (self.mnemonic == 'move'
                    and str(self.operand(2)) == 'sp'))

    def simulate(self, simstate: "SimulationState") -> str:
        try:
            return self.opcode.simulate(self.iaddr, simstate)
        except SU.CHBSimError as e:
            e.instrtxt = str(self)
            raise e

    def __str__(self) -> str:
        return (
            self._stat.rjust(2)
            + '  '
            + self.iaddr.rjust(8)
            + '  '
            + self.mnemonic.ljust(8)
            + ','.join([str(op) for op in self.opcode.operands]))


class MIPSAssembly(Assembly):

    def __init__(
            self,
            app: "MIPSAccess",
            xnode: ET.Element) -> None:
        Assembly.__init__(self, app, xnode)
        self._sorted_instructions: List[int] = []  # list of integer addresses
        # list of integer addresses (reverse)
        self._revsorted_instructions: List[int] = []
        self._instructions: Dict[str, MIPSAssemblyInstruction] = {}

    @property
    def app(self) -> "MIPSAccess":
        return cast("MIPSAccess", self._app)

    @property
    def instructions(self) -> Mapping[str, MIPSAssemblyInstruction]:
        if len(self._instructions) == 0:
            for b in self.xnode.findall("b"):
                for n in b.findall("i"):
                    iaddr = n.get("ia")
                    if iaddr is None:
                        raise UF.CHBError("Instruction without address")
                    opcode = self.app.mipsdictionary.read_xml_mips_opcode(n)
                    stat = n.get("stat", "")
                    self._instructions[iaddr] = MIPSAssemblyInstruction(
                        iaddr, opcode, stat)
        return self._instructions

    @property
    def sorted_instructions(self) -> List[int]:
        if len(self._sorted_instructions) == 0:
            self._sorted_instructions = sorted(
                [int(k, 16) for k in self.instructions])
        return self._sorted_instructions

    @property
    def revsorted_instructions(self) -> List[int]:
        if len(self._revsorted_instructions) == 0:
            self._revsorted_instructions = sorted(
                [int(k, 16) for k in self.instructions], reverse=True)
        return self._revsorted_instructions
