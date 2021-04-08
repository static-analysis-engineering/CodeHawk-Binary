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

from typing import Dict, List, Mapping, Optional, TYPE_CHECKING

import chb.app.Function as F
import chb.app.Cfg as C
import chb.arm.ARMBlock as B
import chb.arm.ARMCfg as CFG
import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.app.AppAccess
    import chb.app.BasicBlock


class ARMFunction(F.Function):

    def __init__(
            self,
            app: "chb.app.AppAccess.AppAccess",
            xnode: ET.Element) -> None:
        F.Function.__init__(self, app, xnode)
        self._cfg: Optional[CFG.ARMCfg] = None
        self._blocks: Dict[str, B.ARMBlock] = {}

    @property
    def blocks(self) -> Mapping[str, "chb.app.BasicBlock.BasicBlock"]:
        if len(self._blocks) == 0:
            xinstrs = self.xnode.find("instructions")
            if xinstrs is None:
                raise UF.CHBError("ARM instructions element missing")
            for n in xinstrs.findall("bl"):
                baddr = n.get("ba")
                if baddr is None:
                    raise UF.CHBError("ARM block address missing from xml")
                self._blocks[baddr] = B.ARMBlock(self, n)
        return self._blocks

    @property
    def cfg(self) -> C.Cfg:
        if self._cfg is None:
            xcfg = self.xnode.find("cfg")
            if xcfg is None:
                raise UF.CHBError("cfg element is missing from arm function")
            self._cfg = CFG.ARMCfg(self, xcfg)
        return self._cfg

    def to_string(
            self,
            bytestring: bool = False,
            sp: bool = False,
            opcodetxt: bool = True,
            hash: bool = False,
            opcodewidth: int = 40) -> str:
        lines: List[str] = []
        for b in sorted(self.blocks):
            lines.append(
                self.blocks[b].to_string(
                    sp=sp, opcodetxt=opcodetxt, opcodewidth=opcodewidth))
            lines.append("-" * 80)
        return "\n".join(lines)
