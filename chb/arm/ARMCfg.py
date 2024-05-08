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
from chb.app.TrampolineInfo import TrampolineInfo
from chb.arm.ARMCfgBlock import ARMCfgBlock, ARMCfgTrampolineBlock
import chb.arm.ARMCfgPath as P

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMFunction import ARMFunction
    from chb.arm.ARMInstruction import ARMInstruction
    from chb.cmdline.PatchResults import PatchEvent


class ARMCfg(Cfg):

    def __init__(
            self,
            armf: "ARMFunction",
            xnode: ET.Element,
            patchevents: Dict[str, "PatchEvent"] = {}) -> None:
        Cfg.__init__(self, armf.faddr, xnode)
        self._armf = armf
        self._blocks: Dict[str, ARMCfgBlock] = {}
        self._patchevents = patchevents

    @property
    def armfunction(self) -> "ARMFunction":
        return self._armf

    @property
    def patchevents(self) -> Dict[str, "PatchEvent"]:
        return self._patchevents

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

    def get_sanitized_address(self, msg: str, a: Optional[str]) -> str:
        if a is None:
            raise UF.CHBError(msg)
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
                baddr = self.get_sanitized_address(
                    "Block address is missing from arm cfg",
                    b.get("ba"))
                blocks[baddr] = ARMCfgBlock(b)

            if len(self.patchevents) > 0:
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
                src = self.get_sanitized_address(
                    "Src address is missing from arm cfg", e.get("src"))
                tgt = self.get_sanitized_address(
                    "Tgt address is missing from arm cfg", e.get("tgt"))
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
        inlinemap: Dict[str, List[str]] = {}
        xedges = self.xnode.find("edges")
        if xedges is None:
            raise UF.CHBError("Edges are missing from cfg xml")
        for e in xedges.findall("e"):
            src = self.get_sanitized_address(
                "Src address is missing from arm cfg", e.get("src"))
            tgt = self.get_sanitized_address(
                "Tgt address is missing from arm cfg", e.get("tgt"))
            localedges.setdefault(src, [])
            localedges[src].append(tgt)
            revedges.setdefault(tgt, [])
            revedges[tgt].append(src)

            # address names of inlined instructions (in payload)
            # multiple distinct full addresses may have the same base address,
            #  in particular, the @F and @T case for predicated instructions.
            if src.startswith("F"):
                baseaddr = src.split("_")[-1]
                inlinemap.setdefault(baseaddr, [])
                if src not in inlinemap[baseaddr]:
                    inlinemap[baseaddr].append(src)

            if tgt.startswith("F"):
                baseaddr = tgt.split("_")[-1]
                inlinemap.setdefault(baseaddr, [])
                if tgt not in inlinemap[baseaddr]:
                    inlinemap[baseaddr].append(tgt)

        def get_inlinemap_addrs(start: str, size: int) -> List[str]:
            s = int(start, 16)
            result: List[str] = []
            for a in inlinemap:
                ai = int(a, 16)
                if ai >= s and ai < s + size:
                    result.append(a)
            return result

        trampolines: Dict[str, TrampolineInfo] = {}

        # mapping from block address to the address of the trampoline it
        # belongs to
        trampolineblocks: Dict[str, str] = {}

        for (baddr, b) in blocks.items():
            if not (baddr in self.patchevents):
                continue

            patchevent = self.patchevents[baddr]
            canonical_cases = list(sorted(patchevent.cases))
            if canonical_cases == []:
                # Not a trampoline
                continue

            trampolines[baddr] = trinfo = TrampolineInfo(patchevent)

            if patchevent.is_trampoline_pair_minimal_2_and_3:
                chklogger.logger.info("Trampoline pair minimal 2 and 3 %s", baddr)
                trinfo.add_role("payload", baddr)
                trampolineblocks[baddr] = baddr
                continue

            trinfo.add_role("setupblock", baddr)
            trampolineblocks[baddr] = baddr

            if not patchevent.has_payload():
                print(
                    "Error: no payload found in patchevent for trampoline @ "
                    + baddr)
                exit(1)

            for (label, addr) in patchevent.dispatch_addresses(baddr).items():
                trinfo.add_role(label, addr)
                trampolineblocks[addr] = baddr

            # Assumes that the payload is in a function called, which is inlined
            # Retrieves the basic blocks of the payload from the inline map, based
            # on the size of the payload

            payloadstart = patchevent.payload.vahex
            payloadsize = patchevent.payload.inserted
            payload_baseaddrs = get_inlinemap_addrs(payloadstart, payloadsize)

            if (
                    len(payload_baseaddrs) == 1
                    and len(inlinemap[payload_baseaddrs[0]]) == 1):
                addr = inlinemap[payload_baseaddrs[0]][0]
                trinfo.add_role("payload", addr)
                trampolineblocks[addr] = baddr
            else:
                for (i, pba) in enumerate(
                        sorted(payload_baseaddrs, key= lambda p: int(p, 16))):
                    if len(inlinemap[pba]) == 1:
                        addr = inlinemap[pba][0]
                        trinfo.add_role("payload-" + str(i), addr)
                        trampolineblocks[addr] = baddr
                    else:
                        for (j, fa) in enumerate(inlinemap[pba]):
                            trinfo.add_role("payload-" + str(i) + "-" + str(j), fa)
                            trampolineblocks[fa] = baddr

            if "fallthrough" in canonical_cases:
                caseaddr = patchevent.label_address(baddr, "case_fallthrough")
                trinfo.add_role("fallthrough", caseaddr)
                trampolineblocks[caseaddr] = baddr

            if "break" in canonical_cases:
                caseaddr = patchevent.label_address(baddr, "case_break")
                trinfo.add_role("breakout", caseaddr)
                trampolineblocks[caseaddr] = baddr

            if "continue" in canonical_cases:
                caseaddr = patchevent.label_address(baddr, "case_continue")
                trinfo.add_role("continuepath", caseaddr)
                trampolineblocks[caseaddr] = baddr

            if "return" in canonical_cases:
                caseaddr = patchevent.label_address(baddr, "case_return")
                trinfo.add_role("returnpath", caseaddr)
                trampolineblocks[caseaddr] = baddr

        cfgedges: Dict[str, List[str]] = {}

        for src in localedges:
            if src in trampolineblocks:
                trampolinesetup = trampolineblocks[src]
                cfgedges.setdefault(trampolinesetup, [])

            for tgt in localedges[src]:
                if (src in trampolineblocks
                        and tgt in trampolineblocks
                        and trampolineblocks[src] == trampolineblocks[tgt]):
                    # blocks are part of the same trampoline
                    taddr = trampolineblocks[src]
                    trampolines[taddr].add_edge(src, tgt)

                elif (src in trampolineblocks
                          and tgt not in trampolineblocks):
                    # trampoline exit
                    trampolinesetup = trampolineblocks[src]
                    cfgedges.setdefault(src, [])
                    cfgedges[trampolinesetup].append(tgt)

                elif (src in trampolines
                      and tgt in trampolineblocks
                      and trampolineblocks[tgt] == src):
                    # trampoline setup block to next block
                    cfgedges.setdefault(src, [])

                else:
                    # add regular edge
                    cfgedges.setdefault(src, [])
                    cfgedges[src].append(tgt)

        for (baddr, b) in blocks.items():
            if baddr not in trampolineblocks and baddr not in trampolines:
                self._blocks[baddr] = b
        for taddr in trampolines:
            trinfo = trampolines[taddr]
            for src in cfgedges:
                for tgt in cfgedges[src]:
                    if tgt == taddr:
                        trinfo.add_prenode(src)
                    elif src == taddr:
                        trinfo.add_postnode(tgt)
            self._blocks[taddr] = ARMCfgTrampolineBlock(self.xnode, trinfo)

        self._edges = cfgedges
