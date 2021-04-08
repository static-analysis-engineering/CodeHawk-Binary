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

from typing import Callable, Dict, List, Mapping, TYPE_CHECKING

import chb.app.BasicBlock as B
import chb.util.fileutil as UF

from chb.arm.ARMInstruction import ARMInstruction

if TYPE_CHECKING:
    import chb.arm.ARMFunction
    import chb.app.Instruction


class ARMBlock(B.BasicBlock):

    def __init__(
            self,
            armf: "chb.arm.ARMFunction.ARMFunction",
            xnode: ET.Element) -> None:
        B.BasicBlock.__init__(self, armf, xnode)
        self._instructions: Dict[str, ARMInstruction] = {}

    @property
    def instructions(self) -> Mapping[str, "chb.app.Instruction.Instruction"]:
        if len(self._instructions) == 0:
            for n in self.xnode.findall("i"):
                iaddr = n.get("ia")
                if iaddr is None:
                    raise UF.CHBError("ARM Instruction without address in xml")
                self._instructions[iaddr] = ARMInstruction(self, n)
        return self._instructions
