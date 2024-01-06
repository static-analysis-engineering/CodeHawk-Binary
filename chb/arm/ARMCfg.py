# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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

from typing import (
    Any, cast, Dict, List, Mapping, Optional, Sequence, TYPE_CHECKING)

from chb.app.Cfg import Cfg
from chb.arm.ARMCfgBlock import ARMCfgBlock, ARMCfgTrampolineBlock
import chb.arm.ARMCfgPath as P

import chb.util.fileutil as UF

astmode: List[str] = []


if TYPE_CHECKING:
    from chb.arm.ARMFunction import ARMFunction
    from chb.arm.ARMInstruction import ARMInstruction
    from chb.cmdline.PatchResults import PatchEvent


# initialized in chb.cmdline.astcmds
patchevents: Dict[str, "PatchEvent"] = {}  # start of wrapper -> patch event


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
        return cast(
            "ARMInstruction", self.armfunction.instruction(block.lastaddr))

    def condition_to_annotated_value(
            self, src: str, b: "ARMInstruction") -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        ftconditions = b.ft_conditions
        if len(ftconditions) == 2:
            result["c"] = ftconditions[1].to_annotated_value()
            result["fb"] = self.edges[src][0]
            result["tb"] = self.edges[src][1]
        return result

    def get_sanitized_address(self, a: str) -> str:
        if "_" in a:
            return a.split("_")[-1]
        else:
            return a

    @property
    def blocks(self) -> Dict[str, ARMCfgBlock]:
        if len(self._blocks) == 0:
            cfgblocks = self.xnode.find("blocks")
            if cfgblocks is None:
                raise UF.CHBError("Blocks are missing from arm cfg xml")
            blocks: Dict[str, ARMCfgBlock] = {}
            for b in cfgblocks.findall("bl"):
                baddr = self.get_sanitized_address(b.get("ba"))
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
                src = self.get_sanitized_address(e.get("src"))
                if src is None:
                    raise UF.CHBError("Src address is missing from cfg")
                tgt = self.get_sanitized_address(e.get("tgt"))
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
        """Assign trampoline blocks based on info in patchevents data."""

        # create original edges locally
        localedges: Dict[str, List[str]] = {}
        revedges: Dict[str, List[str]] = {}
        xedges = self.xnode.find("edges")
        if xedges is None:
            raise UF.CHBError("Edges are missing from cfg xml")
        for e in xedges.findall("e"):
            src = self.get_sanitized_address(e.get("src"))
            if src is None:
                raise UF.CHBError("Src address is missing from cfg")
            tgt = self.get_sanitized_address(e.get("tgt"))
            if tgt is None:
                raise UF.CHBError("Tgt address is missing from cfg")
            localedges.setdefault(src, [])
            localedges[src].append(tgt)
            revedges.setdefault(tgt, [])
            revedges[tgt].append(src)

        trampolines: Dict[str, Dict[str , str]] = {} # setupblock addr -> roles
        trampolineblocks: Dict[str, str] = {}  # block addr -> setupblock addr

        for (baddr, b) in blocks.items():
            if baddr in patchevents:
                patchevent = patchevents[baddr]
                roles: Dict[str, str] = {}

                cases = patchevent.cases
                if len(cases) > 0:
                    if len(cases) == 1 and cases[0] == "fallthrough":
                        # no decision is made

                        trampolines[baddr] = {}
                        trampolines[baddr]["setupblock"] = baddr
                        if patchevent.has_payload():
                            payload = patchevent.payload.vahex
                            trampolines[baddr]["payload"] = payload
                            trampolineblocks[payload] = baddr
                            if payload in localedges:
                                if len(localedges[payload]) == 1:
                                    takedown = localedges[payload][0]
                                    trampolines[baddr]["takedown"] = takedown
                                    trampolineblocks[takedown] = baddr
                                else:
                                    print(
                                        "Error: multiple edges from fallthrough"
                                        + " payload")
                                    exit(1)
                            else:
                                print(
                                    "Error: payload without successors in"
                                    + " fallthrough path event")
                                exit(1)

                        else:
                            print(
                                "Error: fallthrough patchevent without payload")
                            exit(1)
                    elif (len(cases) == 2
                              and "fallthrough" in cases
                              and  "break" in cases):
                         trampolines[baddr] = {}
                         trampolines[baddr]["setupblock"] = baddr
                         if patchevent.has_payload():
                            payload = patchevent.payload.vahex
                            trampolines[baddr]["payload"] = payload
                            trampolineblocks[payload] = baddr
                            if payload in localedges:
                                if len(localedges[payload]) == 1:
                                    decisionblock = localedges[payload][0]
                                    trampolines[
                                        baddr]["decisionblock"] = decisionblock
                                    trampolineblocks[decisionblock] = baddr
                                    if decisionblock in localedges:
                                        decsuccs = localedges[decisionblock]
                                        if len(decsuccs) == 2:
                                            breakout = decsuccs[0]
                                            takedown = decsuccs[1]
                                            trampolines[baddr]["breakout"] = breakout
                                            trampolines[baddr]["takedown"] = takedown
                                            trampolineblocks[takedown] = baddr
                                            trampolineblocks[breakout] = baddr
                                        else:
                                            print(
                                                "Error in breakout/fallthrough"
                                                + " block: number of decision"
                                                + "edges: "
                                                + str(len(decsuccs)))
                                            exit(1)
                                    else:
                                        print(
                                            "Error in breakout/fallthrough"
                                            + " block: decisionblock not found"
                                            + " in localedges")
                                        exit(1)
                                else:
                                    print(
                                        "Error in breakout/falthrough block:"
                                        + "number of payload edges: "
                                        + str(len(localedges[payload])))
                                    exit(1)
                            else:
                                print(
                                    "Error in breakout/fallthrough block:"
                                    + " no outgoing edges found for payload"
                                    + " block")
                                exit(1)
                         else:
                            print(
                                "Error in breakout/fallthrough block:"
                                + " no payload found in patchevent")
                            exit(1)
                    else:
                        print(
                            "Unexpected number of cases in trampoline: "
                            + str(len(cases)))
                        exit(1)
                else:
                    # not a trampoline
                    pass
            else:
                # not a patch event
                pass

        cfgedges: Dict[str, List[str]] = {}

        for src in localedges:
            for tgt in localedges[src]:
                if (src in trampolineblocks
                        and tgt in trampolineblocks
                        and trampolineblocks[src] == trampolineblocks[tgt]):
                    # blocks are part of the same trampoline
                    continue
                elif (src in trampolineblocks
                          and tgt not in trampolineblocks):
                    # trampoline exit
                    trampolinesetup = trampolineblocks[src]
                    cfgedges.setdefault(src, [])
                    cfgedges[trampolinesetup].append(tgt)
                else:
                    # add regular edge
                    cfgedges.setdefault(src, [])
                    cfgedges[src].append(tgt)

        for (baddr, b) in blocks.items():
            if baddr not in trampolineblocks:
                self._blocks[baddr] = b
            elif baddr in trampolines:
                roles = trampolines[baddr]
                self._blocks[baddr] = ARMCfgTrampolineBlock(
                    self.xnode, roles)
                print("DEBUG: trampoline: " + str(self._blocks[baddr]))

        self._edges = cfgedges
