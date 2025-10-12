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
from chb.arm.ARMOpcode import ARMOpcode
from chb.arm.ARMOperand import ARMOperand

import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.arm.ARMAccess import ARMAccess
    from chb.arm.opcodes.ARMNotRecognized import ARMNotRecognized
    from chb.simulation.SimulationState import SimulationState


class ARMAssemblyInstruction(AssemblyInstruction):

    def __init__(
            self,
            iaddr: str,
            opcode: ARMOpcode,
            stat: str = ""):
        AssemblyInstruction.__init__(self, iaddr, stat)
        self._opcode = opcode

    @property
    def opcode(self) -> ARMOpcode:
        return self._opcode

    @property
    def mnemonic(self) -> str:
        return self.opcode.mnemonic_stem

    def mnemonic_extension(self) -> str:
        return self.opcode.mnemonic_extension()

    def unknown_hint(self) -> str:
        if self.mnemonic == "unknown":
            return cast("ARMNotRecognized", self.opcode).unknown_hint
        else:
            raise UF.CHBError("Instruction is not an unknown: " + str(self))

    @property
    def operand_count(self) -> int:
        return len(self.opcode.operands)

    def operand(self, i: int) -> ARMOperand:     # 1-based
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


class ARMAssembly(Assembly):

    def __init__(
            self,
            app: "ARMAccess",
            xnode: ET.Element) -> None:
        Assembly.__init__(self, app, xnode)
        self.sorted_instructions: List[int] = []  # list of integer addresses
        # list of integer addresses (reverse)
        self.revsorted_instructions: List[int] = []
        self._instructions: Dict[str, ARMAssemblyInstruction] = {}

    @property
    def app(self) -> "ARMAccess":
        return cast("ARMAccess", self._app)

    @property
    def instructions(self) -> Mapping[str, ARMAssemblyInstruction]:
        if len(self._instructions) == 0:
            for b in self.xnode.findall("b"):
                for n in b.findall("i"):
                    iaddr = n.get("ia")
                    if iaddr is None:
                        raise UF.CHBError("Instruction without address")
                    opcode = self.app.armdictionary.read_xml_arm_opcode(n)
                    stat = n.get("stat", "")
                    self._instructions[iaddr] = ARMAssemblyInstruction(
                        iaddr, opcode, stat)
            self.sorted_instructions = (
                sorted(int(k, 16) for k in self._instructions.keys()))
            self.revsorted_instructions = sorted(
                self.sorted_instructions, reverse=True)
        return self._instructions
