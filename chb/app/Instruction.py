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
"""Abstract superclass of an assembly instruction in different architectures.

Subclasses:
 - ARMInstruction
 - AsmInstruction
 - MIPSInstruction
"""

import xml.etree.ElementTree as ET

import chb.util.fileutil as UF

from typing import Callable, Dict, List, Sequence, TYPE_CHECKING

if TYPE_CHECKING:
    import chb.app.AppAccess
    import chb.app.BasicBlock
    import chb.app.Function
    import chb.app.Operand
    import chb.app.StackPointerOffset


class Instruction:

    def __init__(
            self,
            block: "chb.app.BasicBlock.BasicBlock",
            xnode: ET.Element) -> None:
        self.block = block
        self.xnode = xnode

    @property
    def iaddr(self) -> str:
        _iaddr = self.xnode.get("ia")
        if _iaddr is None:
            raise UF.CHBError("Instruction address is missing from xml")
        return _iaddr

    @property
    def basicblock(self) -> "chb.app.BasicBlock.BasicBlock":
        return self.block

    @property
    def function(self) -> "chb.app.Function.Function":
        return self.block.function

    @property
    def app(self) -> "chb.app.AppAccess.AppAccess":
        return self.function.app

    @property
    def fndictionary(self) -> "chb.app.FunctionDictionary.FunctionDictionary":
        return self.function.fndictionary

    @property
    def mnemonic(self) -> str:
        raise UF.CHBError("Property mnemonic not implemented for Instruction")

    @property
    def opcodetext(self) -> str:
        raise UF.CHBError("Property opcodetext not implemented for Instruction")

    @property
    def operands(self) -> Sequence["chb.app.Operand.Operand"]:
        raise UF.CHBError("Property operands not implemented for Instruction")

    @property
    def annotation(self) -> str:
        raise UF.CHBError("Property annotation not implemented for Instruction")

    @property
    def stackpointer_offset(self) -> "chb.app.StackPointerOffset.StackPointerOffset":
        raise UF.CHBError(
            "Property stackpointer-offset not implemented for Instruction")

    @property
    def bytestring(self) -> str:
        raise UF.CHBError("Property bytestring not implemented for Instruction")

    @property
    def strings(self) -> List[str]:
        raise UF.CHBError("Property strings not implemented for Instruction")

    def to_string(
            self,
            sp: bool = False,
            opcodetxt: bool = True,
            align: bool = True,
            opcodewidth: int = 40) -> str:
        raise UF.CHBError("To-string not implemented for Instruction")

    def __str__(self) -> str:
        return self.to_string()
