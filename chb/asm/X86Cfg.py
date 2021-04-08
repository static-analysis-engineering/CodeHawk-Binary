# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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
# ------------------------------------------------------------------------------
"""Basic block in control flow graph of x86 function."""

import xml.etree.ElementTree as ET

from typing import Dict, List, TYPE_CHECKING

import chb.app.Cfg as C
import chb.util.fileutil as UF

from chb.asm.X86CfgBlock import X86CfgBlock

if TYPE_CHECKING:
    import chb.asm.AsmFunction

class X86Cfg(C.Cfg):

    def __init__(
            self,
            f: "chb.asm.AsmFunction.AsmFunction",
            xnode: ET.Element) -> None:
        C.Cfg.__init__(self, f, xnode)
        self._blocks: Dict[str, X86CfgBlock] = {}

    @property
    def blocks(self) -> Dict[str, X86CfgBlock]:
        if len(self._blocks) == 0:
            xblocks = self.xnode.find('blocks')
            if xblocks is None:
                raise UF.CHBError("Element blocks missing in X86Cfg")
            for b in xblocks.findall("bl"):
                baddr = b.get("ba")
                if baddr is None:
                    raise UF.CHBError("Attribute ba missing in Cfg block")
                self._blocks[baddr] = X86CfgBlock(self, b)
        return self._blocks

    def __str__(self) -> str:
        lines: List[str] = []
        return (str(self.blocks) + '\n' + str(self.edges))
