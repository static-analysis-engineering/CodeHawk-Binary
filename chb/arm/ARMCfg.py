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

from typing import Any, cast, Dict, List, Optional, TYPE_CHECKING

from chb.app.Cfg import Cfg
from chb.arm.ARMCfgBlock import ARMCfgBlock
import chb.arm.ARMCfgPath as P

import chb.util.fileutil as UF


if TYPE_CHECKING:
    from chb.arm.ARMFunction import ARMFunction
    from chb.arm.ARMInstruction import ARMInstruction


class ARMCfg(Cfg):

    def __init__(self,
                 armf: "ARMFunction",
                 xnode: ET.Element) -> None:
        Cfg.__init__(self, armf.faddr, xnode)
        self._armf = armf
        self._blocks: Dict[str, ARMCfgBlock] = {}

    @property
    def armfunction(self) -> "ARMFunction":
        return self._armf

    def branch_instruction(self, baddr: str) -> "ARMInstruction":
        block = self.blocks[baddr]
        return cast("ARMInstruction", self.armfunction.instruction(block.lastaddr))

    def condition_to_annotated_value(
            self, src: str, b: "ARMInstruction") -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        ftconditions = b.ft_conditions
        if len(ftconditions) == 2:
            result["c"] = ftconditions[1].to_annotated_value()
            result["fb"] = self.edges[src][0]
            result["tb"] = self.edges[src][1]
        return result

    @property
    def blocks(self) -> Dict[str, ARMCfgBlock]:
        if len(self._blocks) == 0:
            cfgblocks = self.xnode.find("blocks")
            if cfgblocks is None:
                raise UF.CHBError("Blocks are missing from arm cfg xml")
            for b in cfgblocks.findall("bl"):
                baddr = b.get("ba")
                if baddr is None:
                    raise UF.CHBError("Block address is missing from arm cfg")
                self._blocks[baddr] = ARMCfgBlock(self, b)
        return self._blocks

    def conditions(self) -> Dict[str, Dict[str, str]]:
        result: Dict[str, Dict[str, str]] = {}
        for src in self.edges:
            if len(self.edges[src]) > 1:
                brinstr = self.branch_instruction(src)
                result[src] = self.condition_to_annotated_value(
                    src, brinstr)
        return result
