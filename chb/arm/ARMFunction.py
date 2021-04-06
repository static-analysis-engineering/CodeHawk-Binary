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

from typing import Dict, List, Optional, TYPE_CHECKING

import chb.arm.ARMBlock as B
import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.app.AppAccess


class ARMFunction:

    def __init__(
            self,
            app: "chb.app.AppAccess.AppAccess",
            xnode: ET.Element):
        self.app = app
        self.xnode = xnode
        self._blocks: Dict[str, B.ARMBlock] = {}

    @property
    def faddr(self) -> str:
        faddr = self.xnode.get("a")
        if faddr is None:
            raise UF.CHBError("Arm function address is missing from xml")
        return faddr

    @property
    def blocks(self) -> Dict[str, B.ARMBlock]:
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

    def has_name(self) -> bool:
        return self.app.functionsdata.has_name(self.faddr)

    def get_names(self) -> List[str]:
        if self.has_name():
            return self.app.functionsdata.get_names(self.faddr)
        else:
            return []

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
