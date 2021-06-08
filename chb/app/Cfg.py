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
"""Abstract superclass of control flow graph.

Subclasses:
  - ARMCfg
  - MIPSCfg
"""

import xml.etree.ElementTree as ET

from typing import Dict, List, Mapping, Sequence

from chb.app.CfgBlock import CfgBlock

import chb.util.fileutil as UF


class Cfg:

    def __init__(
            self,
            xnode: ET.Element) -> None:
        self.xnode = xnode
        self._edges: Dict[str, List[str]] = {}

    @property
    def blocks(self) -> Mapping[str, CfgBlock]:
        raise UF.CHBError("Property blocks not implemented for Cfg")

    @property
    def edges(self) -> Mapping[str, Sequence[str]]:
        if len(self._edges) == 0:
            xedges = self.xnode.find("edges")
            if xedges is None:
                raise UF.CHBError("Edges are missing from cfg xml")
            for e in xedges.findall("e"):
                src = e.get("src")
                if src is None:
                    raise UF.CHBError("Src address is missing from cfg")
                tgt = e.get("tgt")
                if tgt is None:
                    raise UF.CHBError("Tgt address is missing from cfg")
                self._edges.setdefault(src, [])
                self._edges[src].append(tgt)
        return self._edges

    def max_loop_level(self) -> int:
        return max([len(self.blocks[b].looplevels) for b in self.blocks])

    def has_loop_level(self, baddr: str) -> bool:
        if baddr in self.blocks:
            return len(self.blocks[baddr].looplevels) > 0
        else:
            return False

    def has_loops(self) -> bool:
        return self.max_loop_level() > 0

    def loop_levels(self, baddr: str) -> Sequence[str]:
        if baddr in self.blocks:
            return self.blocks[baddr].looplevels
        else:
            raise UF.CHBError("Blockaddress " + baddr + " not found in cfg")

    def successors(self, src: str) -> Sequence[str]:
        if src in self._edges:
            return self._edges[src]
        else:
            return []

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Basic blocks: ")
        for b in self.blocks:
            lines.append(str(b))
        lines.append("\nEdges: ")
        for e in self.edges:
            lines.append(e.ljust(6) + "  [" + ", ".join(self.edges[e]) + "]")
        return "\n".join(lines)
