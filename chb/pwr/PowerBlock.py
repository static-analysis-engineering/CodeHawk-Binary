# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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

from typing import Callable, Dict, List, Mapping, Sequence, TYPE_CHECKING

from chb.app.BasicBlock import BasicBlock

import chb.util.fileutil as UF

from chb.invariants.XXpr import XXpr

from chb.pwr.PowerDictionary import PowerDictionary
from chb.pwr.PowerInstruction import PowerInstruction

if TYPE_CHECKING:
    from chb.pwr.PowerFunction import PowerFunction


class PowerBlock(BasicBlock):

    def __init__(self, pwrf: "PowerFunction", xnode: ET.Element) -> None:
        BasicBlock.__init__(self, xnode)
        self._pwrf = pwrf
        self._instructions: Dict[str, PowerInstruction] = {}

    @property
    def pwrfunction(self) -> "PowerFunction":
        return self._pwrf

    @property
    def pwrdictionary(self) -> PowerDictionary:
        return self.pwrfunction.pwrdictionary

    @property
    def instructions(self) -> Mapping[str, PowerInstruction]:
        if len(self._instructions) == 0:
            for n in self.xnode.findall("i"):
                iaddr = n.get("ia")
                if iaddr is None:
                    raise UF.CHBError("Power instruction without address in xml")
                self._instructions[iaddr] = PowerInstruction(self, n)
        return self._instructions

    def to_string(
            self,
            bytes: bool = False,
            opcodetxt: bool = True,
            opcodewidth: int = 40,
            sp: bool = True) -> str:
        lines: List[str] = []
        for (ia, instr) in sorted(self.instructions.items()):
            pinstr = instr.to_string(
                bytes=bytes,
                opcodetxt=opcodetxt,
                opcodewidth=opcodewidth,
                sp=sp)
            lines.append(str(ia).rjust(10) + "  " + pinstr)
        return "\n".join(lines)
