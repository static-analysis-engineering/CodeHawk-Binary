# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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

from typing import Callable, Dict, List, Optional, Sequence, TYPE_CHECKING

from chb.app.FunctionDictionary import FunctionDictionary
from chb.app.Instruction import Instruction
from chb.app.InstrXData import InstrXData
from chb.app.Operand import Operand
from chb.app.StackPointerOffset import StackPointerOffset

from chb.arm.ARMDictionary import ARMDictionary
from chb.arm.ARMOpcode import ARMOpcode
from chb.arm.ARMOperand import ARMOperand

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
        return self.opcode.mnemonic + self.opcode.mnemonic_extension

    @property
    def opcodetext(self) -> str:
        try:
            operands = self.operands
            return self.mnemonic.ljust(8) + ",".join([str(op) for op in operands])
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
    def bytestring(self) -> str:
        return self.armdictionary.read_xml_arm_bytestring(self.xnode)

    @property
    def is_call_instruction(self) -> bool:
        raise UF.CHBError("is-call-instruction: not implemented")

    @property
    def is_return_instruction(self) -> bool:
        raise UF.CHBError("is-return-instruction: not implemented")

    @property
    def is_branch_instruction(self) -> bool:
        return self.opcode.is_branch_instruction

    def return_expr(self) -> XXpr:
        raise UF.CHBError("get-return-expr: not implemented")

    @property
    def ft_conditions(self) -> Sequence[XXpr]:
        return []

    @property
    def annotation(self) -> str:
        return self.opcode.annotation(self.xdata).ljust(40)

    @property
    def stackpointer_offset(self) -> StackPointerOffset:
        return self.armfunctiondictionary.read_xml_sp_offset(self.xnode)

    @property
    def strings_referenced(self) -> Sequence[str]:
        return []

    @property
    def call_arguments(self) -> Sequence[XXpr]:
        return []

    def to_string(
            self,
            bytes: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 25,
            sp: bool = False) -> str:
        pbytes = self.bytestring.ljust(10) + "  " if bytes else ""
        pesp = str(self.stackpointer_offset) + "  " if sp else ""
        popcode = (
            self.opcodetext.ljust(opcodewidth) if opcodetxt else "")
        return pesp + pbytes + popcode + self.annotation
