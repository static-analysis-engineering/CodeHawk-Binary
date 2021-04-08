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
"""Control flow graph of ARM function."""

import xml.etree.ElementTree as ET

import chb.app.Cfg as C
import chb.arm.ARMCfgBlock as B
import chb.arm.ARMCfgPath as P
import chb.util.fileutil as UF

from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import chb.arm.ARMFunction


class ARMCfg(C.Cfg):

    def __init__(self,
                 armf: "chb.arm.ARMFunction.ARMFunction",
                 xnode: ET.Element) -> None:
        C.Cfg.__init__(self, armf, xnode)
        self._blocks: Dict[str, B.ARMCfgBlock] = {}

    @property
    def blocks(self) -> Dict[str, B.ARMCfgBlock]:
        if len(self._blocks) == 0:
            cfgblocks = self.xnode.find("blocks")
            if cfgblocks is None:
                raise UF.CHBError("Blocks are missing from arm cfg xml")
            for b in cfgblocks.findall("bl"):
                baddr = b.get("ba")
                if baddr is None:
                    raise UF.CHBError("Block address is missing from arm cfg")
                self._blocks[baddr] = B.ARMCfgBlock(self, b)
        return self._blocks
