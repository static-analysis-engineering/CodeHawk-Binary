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

from typing import Callable, Dict, List, TYPE_CHECKING

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    import chb.arm.ARMBlock
    import chb.arm.ARMOperand


class ARMInstruction:

    def __init__(
            self,
            armb: "chb.arm.ARMBlock.ARMBlock",
            xnode: ET.Element) -> None:
        self.armblock = armb
        self.armfunction = self.armblock.armfunction
        self.xnode = xnode
        self.iaddr = self.xnode.get("ia")
        self.armdictionary = self.armfunction.app.armdictionary

    def get_mnemonic(self) -> str:
        opcode = self.armdictionary.read_xml_arm_opcode(self.xnode)
        return opcode.get_mnemonic()

    def get_opcode_text(self) -> str:
        try:
            mnemonic = self.get_mnemonic()
            operands = self.get_operands()
            return mnemonic.ljust(8) + ",".join([str(op) for op in operands])
        except IT.IndexedTableError as e:
            opcode = self.armdictionary.read_xml_arm_opcode(self.xnode)
            raise UF.CHBError(
                "Error for ARM opcode "
                + str(opcode)
                + ": "
                + str(e))

    # -- STUB --
    def get_sp_offset(self) -> int:
        return 0

    # -- STUB --
    def get_operands(self) -> List["chb.arm.ARMOperand.ARMOperand"]:
        opcode = self.armdictionary.read_xml_arm_opcode(self.xnode)
        return opcode.get_operands()

    # -- STUB --
    def get_annotation(self) -> str:
        return self.get_opcode_text()

    def to_string(
            self,
            sp: bool = False,
            opcodetxt: bool = True,
            align: bool = True,
            opcodewidth: int = 40) -> str:
        pesp = str(self.get_sp_offset()) + "  " if sp else ""
        if align:
            popcode = (
                self.get_opcode_text().ljust(opcodewidth) if opcodetxt else "")
            return pesp + popcode + self.get_annotation()
        else:
            popcode = self.get_opcode_text()
            return popcode + "  [[" + self.get_annotation() + "]]"

    def __str__(self): return self.to_string()
