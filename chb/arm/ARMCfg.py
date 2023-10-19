# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs LLC
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

from typing import Any, cast, Dict, List, Mapping, Optional, Sequence, TYPE_CHECKING

from chb.app.Cfg import Cfg
from chb.arm.ARMCfgBlock import ARMCfgBlock, ARMCfgTrampolineBlock
import chb.arm.ARMCfgPath as P

import chb.util.fileutil as UF

astmode: List[str] = []

if TYPE_CHECKING:
    from chb.arm.ARMFunction import ARMFunction
    from chb.arm.ARMInstruction import ARMInstruction


class ARMCfg(Cfg):

    def __init__(self, armf: "ARMFunction", xnode: ET.Element) -> None:
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
            blocks: Dict[str, ARMCfgBlock] = {}
            for b in cfgblocks.findall("bl"):
                baddr = b.get("ba")
                if baddr is None:
                    raise UF.CHBError("Block address is missing from arm cfg")
                blocks[baddr] = ARMCfgBlock(b)
            if len(astmode) > 0:
                if any(b.is_in_trampoline for b in blocks.values()):
                    self.set_trampoline_blocks(blocks)
                else:
                    self._blocks = blocks
            else:
                self._blocks = blocks
        return self._blocks

    @property
    def edges(self) -> Mapping[str, Sequence[str]]:
        if len(self._edges) == 0:
            # ensure that blocks is called before edges in case nodes are to be
            # collapsed into a trampoline, which will also set the appropriate
            # connectivity
            blocks = self.blocks
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

    def conditions(self) -> Dict[str, Dict[str, str]]:
        result: Dict[str, Dict[str, str]] = {}
        for src in self.edges:
            if len(self.edges[src]) > 1:
                brinstr = self.branch_instruction(src)
                result[src] = self.condition_to_annotated_value(
                    src, brinstr)
        return result

    def set_trampoline_blocks(
            self, blocks: Dict[str, ARMCfgBlock]) -> None:
        """Assign the roles of blocks that are part of a recognized trampoline.

        Currently the following types of trampolines are recognized:
        (1) breakout
            (cfg) => (setup) => (payload) => (decision) => (takedown) => (cfg)
                                                        => (breakout)
        (2) conditional
        """

        # create original edges locally
        localedges: Dict[str, List[str]] = {}
        revedges: Dict[str, List[str]] = {}
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
            localedges.setdefault(src, [])
            localedges[src].append(tgt)
            revedges.setdefault(tgt, [])
            revedges[tgt].append(src)

        roles: Dict[str, str] = {}

        setupblock: Optional[str] = None
        takedownblock: Optional[str] = None
        payloadblock: Optional[str] = None
        decisionblock: Optional[str] = None
        breakoutblock: Optional[str] = None

        # determine type of trampoline

        pcount: int = 0
        for (baddr, b) in blocks.items():
            if b.is_in_trampoline:
                if baddr.startswith("F"): pcount += 1

        if pcount == 1:
            trampoline_type = "breakout"
        elif pcount == 3:
            trampoline_type = "conditional"
        else:
            print("Trampoline type not recognized")
            return

        # determine setup block
        for (baddr, b) in blocks.items():
            if b.is_in_trampoline:
                if baddr in revedges:
                    revb = revedges[baddr]
                if all(not blocks[pb].is_in_trampoline for pb in revb):
                    setupblock = baddr
                    roles["setup"] = baddr

        if not setupblock:
            print("no setup block found")
            return

        # determine payload block
        if setupblock in localedges:
            if len(localedges[setupblock]) == 1:
                payloadblock = localedges[setupblock][0]
                roles["payload"] = payloadblock

        # determine trampoline decision block
        if payloadblock in localedges:
            if len(localedges[payloadblock]) == 1:
                decisionblock = localedges[payloadblock][0]
                roles["decision"] = decisionblock

        # determine takedown block
        if decisionblock in localedges:
            if len(localedges[decisionblock]) == 2:
                for succ in localedges[decisionblock]:
                    if succ in localedges:
                        if len(localedges[succ]) == 1:
                            if not blocks[(localedges[succ][0])].is_in_trampoline:
                                takedownblock = succ
                                roles["takedown"] = takedownblock

        # determine breakout block
        if decisionblock in localedges:
            if len(localedges[decisionblock]) == 2:
                for succ in localedges[decisionblock]:
                    if succ != takedownblock:
                        roles["breakout"] = succ
                        breakoutblock = succ
                    else:
                        continue

        cfgedges: Dict[str, List[str]] = {}

        for src in localedges:
            for tgt in localedges[src]:
                if not blocks[src].is_in_trampoline and blocks[tgt].is_in_trampoline:
                    trampolineaddr = tgt
                    cfgedges.setdefault(src, [])
                    cfgedges[src].append(tgt)
                elif blocks[src].is_in_trampoline and not blocks[tgt].is_in_trampoline:
                    cfgedges[setupblock] = [tgt]
                elif blocks[src].is_in_trampoline and blocks[tgt].is_in_trampoline:
                    continue
                else:
                    cfgedges.setdefault(src, [])
                    cfgedges[src].append(tgt)

        for (baddr, b) in blocks.items():
            if not b.is_in_trampoline:
                self._blocks[baddr] = b
            elif baddr == setupblock:
                self._blocks[baddr] = ARMCfgTrampolineBlock(
                    self.xnode, roles)

        self._edges = cfgedges
