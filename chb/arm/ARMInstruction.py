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

from typing import Callable, Dict, List, Sequence, TYPE_CHECKING

import chb.app.Instruction as I
import chb.app.Operand as O
import chb.app.StackPointerOffset as S
import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    import chb.arm.ARMBlock
    import chb.arm.ARMOperand


class ARMInstruction(I.Instruction):

    def __init__(
            self,
            armb: "chb.arm.ARMBlock.ARMBlock",
            xnode: ET.Element) -> None:
        I.Instruction.__init__(self, armb, xnode)
        self.armdictionary = self.function.app.armdictionary

    @property
    def mnemonic(self) -> str:
        opcode = self.armdictionary.read_xml_arm_opcode(self.xnode)
        return opcode.get_mnemonic()

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
                + self.function.faddr
                + " at address "
                + self.iaddr
                + ": "
                + str(e))

    @property
    def operands(self) -> Sequence["chb.arm.ARMOperand.ARMOperand"]:
        opcode = self.armdictionary.read_xml_arm_opcode(self.xnode)
        return opcode.get_operands()

    @property   # -- STUB --
    def annotation(self) -> str:
        return ""

    @property   # -- STUB --
    def stackpointer_offset(self) -> S.StackPointerOffset:
        return self.function.fndictionary.read_xml_sp_offset(self.xnode)

    def to_string(
            self,
            sp: bool = False,
            opcodetxt: bool = True,
            align: bool = True,
            opcodewidth: int = 40) -> str:
        pesp = str(self.stackpointer_offset) + "  " if sp else ""
        if align:
            popcode = (
                self.opcodetext.ljust(opcodewidth) if opcodetxt else "")
            return pesp + popcode + self.annotation
        else:
            popcode = self.opcodetext
            return popcode + "  [[" + self.annotation + "]]"
