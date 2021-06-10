# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
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
"""MIPS Control flow graph."""

import xml.etree.ElementTree as ET

from typing import Any, cast, Dict, List, Mapping, Optional, TYPE_CHECKING

from chb.app.Cfg import Cfg

from chb.invariants.XXpr import XXpr

from chb.mips.MIPSCfgBlock import MIPSCfgBlock
from chb.mips.MIPSInstruction import MIPSInstruction
from chb.mips.MIPSCfgPath import MIPSCfgPath

import chb.util.fileutil as UF
import chb.util.graphutil as UG


if TYPE_CHECKING:
    from chb.mips.MIPSFunction import MIPSFunction


class MIPSCfg(Cfg):

    def __init__(
            self,
            f: "MIPSFunction",
            xnode: ET.Element) -> None:
        Cfg.__init__(self, xnode)
        self._f = f
        self._blocks: Dict[str, MIPSCfgBlock] = {}
        self._edges: Dict[str, List[str]] = {}

    @property
    def function(self) -> "MIPSFunction":
        return self._f

    @property
    def blocks(self) -> Mapping[str, MIPSCfgBlock]:
        if len(self._blocks) == 0:
            xblocks = self.xnode.find('blocks')
            if xblocks is None:
                raise UF.CHBError("Element blocks missing in MIPSCfg")
            for b in xblocks.findall("bl"):
                baddr = b.get("ba")
                if baddr is None:
                    raise UF.CHBError("Attribute ba missing in Cfg block")
                self._blocks[baddr] = MIPSCfgBlock(self, b)
        return self._blocks

    def paths(
            self,
            baddr: str,
            maxtime: Optional[int] = None) -> List[MIPSCfgPath]:
        """Returns a path from function entry to blockaddr baddr."""
        g = UG.DirectedGraph(list(self.blocks.keys()), self.edges)
        g.find_paths(self.function.faddr, baddr, maxtime=maxtime)
        return [MIPSCfgPath(self, p) for p in g.paths]

    def branch_instruction(self, n: str) -> MIPSInstruction:
        block = self.blocks[n]
        iaddr = int(block.lastaddr, 16) - 4  # account for delay slot
        return cast(
            MIPSInstruction, self.function.instruction(hex(iaddr)))

    def condition_to_annotated_value(
            self, src: str, b: MIPSInstruction) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        ftconditions = b.ft_conditions
        if len(ftconditions) == 2:
            result['c'] = ftconditions[1].to_annotated_value()
            result['fb'] = self.edges[src][0]
            result['tb'] = self.edges[src][1]
        return result

    def conditions(self) -> Dict[str, Dict[str, str]]:
        result: Dict[str, Dict[str, str]] = {}
        for src in self.edges:
            if len(self.edges[src]) > 1:
                brinstr = self.branch_instruction(src)
                result[brinstr.iaddr] = self.condition_to_annotated_value(
                    src, brinstr)
        return result

    def condition(self, src: str, tgt: str) -> Optional[XXpr]:
        """Returns the condition, if any, that leads from src to tgt."""

        if len(self.edges[src]) > 1:
            brinstr = self.branch_instruction(src)
            ftconditions = brinstr.ft_conditions
            if len(ftconditions) == 2:
                for i, t in enumerate(self.edges[src]):
                    if tgt == t:
                        return ftconditions[i]
            else:
                raise UF.CHBError("Error in Cfg.condition")

        return None

    def path_conditions(self, path: List[str]) -> Dict[str, XXpr]:
        result: Dict[str, XXpr] = {}
        for i in range(len(path) - 1):
            c = self.condition(path[i], path[i+1])
            if c is None:
                continue
            result[path[i]] = c
        return result

    def __str__(self) -> str:
        lines: List[str] = []
        return (str(self.blocks) + '\n' + str(self.edges))
