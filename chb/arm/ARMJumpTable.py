# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2024  Aarno Labs
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

from typing import Dict, List, Tuple, TYPE_CHECKING

from chb.app.JumpTables import JumpTable

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.arm.ARMFunction import ARMFunction
    from chb.arm.ARMOperand import ARMOperand


class ARMJumpTable(JumpTable):

    def __init__(self, fn: "ARMFunction", xnode: ET.Element) -> None:
        self._fn = fn
        self._xnode = xnode
        self._indexed_targets: Dict[str, List[int]] = {}

    @property
    def armfunction(self) -> "ARMFunction":
        return self._fn

    @property
    def index_operand(self) -> "ARMOperand":
        opix = self._xnode.get("indexopix")
        if opix is None:
            raise UF.CHBError("ARMJumpTable does not have index operand")
        return self.armfunction.armdictionary.arm_operand(int(opix))

    @property
    def va(self) -> str:
        return self._xnode.get("va", "?")

    @property
    def startaddr(self) -> str:
        return self._xnode.get("start", "?")

    @property
    def endaddr(self) -> str:
        return self._xnode.get("end", "?")

    @property
    def default_target(self) -> str:
        return self._xnode.get("default", "?")

    @property
    def indexed_targets(self) -> Dict[str, List[int]]:
        if len(self._indexed_targets) == 0:
            for n in self._xnode.findall("tgt"):
                addr = n.get("a")
                cvs = n.get("cvs")
                if addr is not None and cvs is not None:
                    indices = [int(v) for v in cvs.split(",")]
                    self._indexed_targets[addr] = indices
        return self._indexed_targets

    def __str__(self) -> str:
        lines: List[str] = []
        for (va, indices) in self.indexed_targets.items():
            lines.append(va + "  " + ", ".join(str(i) for i in indices))
        return "\n".join(lines)


