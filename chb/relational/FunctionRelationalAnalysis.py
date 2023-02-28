# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs, LLC
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
"""Compares two related functions in two binaries."""

from typing import Dict, List, Mapping, Optional, Set, Tuple, TYPE_CHECKING

from chb.relational.BlockRelationalAnalysis import BlockRelationalAnalysis
from chb.relational.CfgMatcher import CfgMatcher

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.BasicBlock import BasicBlock
    from chb.app.Cfg import Cfg
    from chb.app.CfgBlock import CfgBlock
    from chb.app.Function import Function
    from chb.app.Instruction import Instruction


class FunctionRelationalAnalysis:

    def __init__(
            self,
            app1: "AppAccess",
            fn1: "Function",
            app2: "AppAccess",
            fn2: "Function") -> None:
        self._app1 = app1
        self._app2 = app2
        self._fn1 = fn1
        self._fn2 = fn2
        self._cfg1: Optional["Cfg"] = None
        self._cfg2: Optional["Cfg"] = None
        self._cfgblocks1: Mapping[str, "CfgBlock"] = {}
        self._cfgblocks2: Mapping[str, "CfgBlock"] = {}
        self._edges1: Set[Tuple[str, str]] = set([])
        self._edges2: Set[Tuple[str, str]] = set([])
        self._blockmapping: Dict[str, str] = {}
        self._blockanalyses: Dict[str, BlockRelationalAnalysis] = {}
        self._cfgmatcher: Optional[CfgMatcher] = None

    @property
    def app1(self) -> "AppAccess":
        return self._app1

    @property
    def app2(self) -> "AppAccess":
        return self._app2

    @property
    def faddr1(self) -> str:
        return self.fn1.faddr

    @property
    def faddr2(self) -> str:
        return self.fn2.faddr

    @property
    def offset(self) -> int:
        """Return the difference between the two function addresses."""

        return int(self.faddr2, 16) - int(self.faddr1, 16)

    @property
    def moved(self) -> bool:
        return self.faddr1 != self.faddr2

    @property
    def same_endianness(self) -> bool:
        return self.app1.header.is_big_endian == self.app2.header.is_big_endian

    def address2_align(self, addr2: str) -> str:
        """Return the corresponding address in fn2 by adding the offset."""

        if addr2.startswith("F") or addr2.startswith("T"):
            return "?"
        else:
            return hex(int(addr2, 16) - self.offset)

    def edge2_align(self, e2: Tuple[str, str]) -> Tuple[str, str]:
        return (self.address2_align(e2[0]), self.address2_align(e2[1]))

    @property
    def fn1(self) -> "Function":
        return self._fn1

    @property
    def fn2(self) -> "Function":
        return self._fn2

    @property
    def basic_blocks1(self) -> Mapping[str, "BasicBlock"]:
        return self.fn1.blocks

    @property
    def basic_blocks2(self) -> Mapping[str, "BasicBlock"]:
        return self.fn2.blocks

    @property
    def cfg1(self) -> "Cfg":
        if not self._cfg1:
            self._cfg1 = self.fn1.cfg
        return self._cfg1

    @property
    def cfg2(self) -> "Cfg":
        if not self._cfg2:
            self._cfg2 = self.fn2.cfg
        return self._cfg2

    @property
    def cfg_blocks1(self) -> Mapping[str, "CfgBlock"]:
        if len(self._cfgblocks1) == 0:
            self._cfgblocks1 = self.cfg1.blocks
        return self._cfgblocks1

    @property
    def cfg_blocks2(self) -> Mapping[str, "CfgBlock"]:
        if len(self._cfgblocks2) == 0:
            self._cfgblocks2 = self.cfg2.blocks
        return self._cfgblocks2

    @property
    def edges1(self) -> Set[Tuple[str, str]]:
        if len(self._edges1) == 0:
            self._edges1 = self.cfg1.edges_as_set
        return self._edges1

    @property
    def edges2(self) -> Set[Tuple[str, str]]:
        if len(self._edges2) == 0:
            self._edges2 = self.cfg2.edges_as_set
        return self._edges2

    @property
    def branchconditions1(self) -> Mapping[str, "Instruction"]:
        return self.fn1.branchconditions

    @property
    def branchconditions2(self) -> Mapping[str, "Instruction"]:
        return self.fn2.branchconditions

    @property
    def cfgmatcher(self) -> CfgMatcher:
        if self._cfgmatcher is None:
            self._cfgmatcher = CfgMatcher(
                self.app1,
                self.fn1,
                self.cfg1,
                self.app2,
                self.fn2,
                self.cfg2,
                {},
                {})
        return self._cfgmatcher

    @property
    def is_md5_equal(self) -> bool:
        if self.same_endianness:
            return self.fn1.md5 == self.fn2.md5
        else:
            return self.fn1.md5 == self.fn2.rev_md5

    @property
    def is_structurally_equivalent(self) -> bool:
        """Return true if the control flow graphs are address-isomorphic."""

        def nolog(s: str) -> None:
            pass

        bbaddrs1 = self.basic_blocks1.keys()
        bbaddrs2 = [
            self.address2_align(b) for b in self.basic_blocks2.keys()]

        bdiff = set(bbaddrs2) - set(bbaddrs1)
        if len(bdiff) == 0:

            ediff = self.edges1.symmetric_difference(
                set(self.edge2_align(e) for e in self.edges2))
            if len(ediff) == 0:
                return True
            elif (len(self.edges1) > len(self.edges2)):
                ndiff = len(self.edges1) - len(self.edges2)
                nolog(
                    "Function-1 "
                    + self.faddr1
                    + " has "
                    + str(ndiff)
                    + " more edge(s) than "
                    + self.faddr2
                    + ": "
                    + ", ".join(str(e) for e in ediff))
                return False
            elif (len(self.edges2) > len(self.edges1)):
                ndiff = len(self.edges2) - len(self.edges1)
                nolog(
                    "Function-2 "
                    + self.faddr2
                    + " has "
                    + str(ndiff)
                    + " more edge(s) than "
                    + self.faddr2
                    + ": "
                    + ", ".join(str(e) for e in ediff))
                return False

            else:
                print("Differences in block addresses: " + ", ".join(bdiff))
                return False

        return False

    @property
    def is_cfg_isomorphic(self) -> bool:
        """Return true if there exists a graph isomorphism between the cfgs."""

        return (
            self.is_structurally_equivalent
            or self.cfgmatcher.is_cfg_isomorphic)

    @property
    def block_mapping(self) -> Mapping[str, str]:
        if len(self._blockmapping) == 0:
            if self.is_structurally_equivalent:
                for b1 in self.basic_blocks1:
                    self._blockmapping[b1] = hex(int(b1, 16) + self.offset)
            elif self.is_cfg_isomorphic:
                try:
                    mapping = self.cfgmatcher.blockmapping
                    for b1 in self.basic_blocks1:
                        self._blockmapping[b1] = mapping[b1]
                except KeyError as e:
                    print(
                        "Error in mapping returned from cfg matcher of "
                        + self.faddr1
                        + " ("
                        + str(len(self.basic_blocks1))
                        + ") and "
                        + self.faddr2
                        + " ("
                        + str(len(self.basic_blocks2))
                        + "): "
                        + str(e))
        return self._blockmapping

    @property
    def block_analyses(self) -> Mapping[str, BlockRelationalAnalysis]:
        if len(self._blockanalyses) == 0:
            for (b1, b2) in self.block_mapping.items():
                self._blockanalyses[b1] = BlockRelationalAnalysis(
                    self.app1,
                    self.basic_blocks1[b1],
                    self.app2,
                    self.basic_blocks2[b2])
        return self._blockanalyses

    def blocks_changed(self) -> List[str]:
        """Return a list of block addresses that are not md5-equal."""

        result: List[str] = []
        for baddr in self.block_analyses:
            if not self.block_analyses[baddr].is_md5_equal:
                result.append(baddr)
        return result

    def instructions_changed(self, callees: List[str] = []) -> int:
        """Return the number of instructions changed in this function."""

        total: int = 0
        if self.is_structurally_equivalent:
            for (baddr1, baddr2) in self.block_mapping.items():
                blra = self.block_analyses[baddr1]
                if not blra.is_md5_equal:
                    total += len(blra.instrs_changed(callees))
        return total

    def report(self, showinstructions: bool, callees: List[str] = []) -> str:
        lines: List[str] = []
        lines.append(
            "block".ljust(12)
            + "moved".ljust(12)
            + "md5-equivalent".ljust(20)
            + "instrs-changed".ljust(20))
        lines.append("-" * 80)
        if self.is_structurally_equivalent:
            for (baddr1, baddr2) in self.block_mapping.items():
                blra = self.block_analyses[baddr1]
                if baddr1 == baddr2:
                    moved = "no"
                else:
                    moved = baddr2
                md5eq = "yes" if blra.is_md5_equal else "no"
                if md5eq == "no":
                    instrs_changed = len(blra.instrs_changed(callees))
                    instrcount = len(blra.b1.instructions)
                    insch = str(instrs_changed) + "/" + str(instrcount)
                else:
                    insch = "-"
                lines.append(
                    baddr1.ljust(12)
                    + moved.ljust(16)
                    + md5eq.ljust(18)
                    + insch.ljust(20))

            if showinstructions:
                for baddr in self.blocks_changed():
                    blra = self.block_analyses[baddr]
                    if not blra.is_md5_equal:
                        if len(blra.instrs_changed(callees)) > 0:
                            lines.append(
                                "\nInstructions changed in block "
                                + baddr
                                + " ("
                                + str(len(blra.instrs_changed(callees)))
                                + "):")
                            lines.append(blra.report(callees))
                            lines.append("")
        else:
            cfgmatcher = CfgMatcher(
                self.app1,
                self.fn1,
                self.cfg1,
                self.app2,
                self.fn2,
                self.cfg2,
                {},
                {})
            for baddr1 in sorted(self.basic_blocks1):
                if baddr1 in cfgmatcher.blockmapping:
                    baddr2 = cfgmatcher.blockmapping[baddr1]
                    self._blockanalyses[baddr1] = BlockRelationalAnalysis(
                        self.app1,
                        self.basic_blocks1[baddr1],
                        self.app2,
                        self.basic_blocks2[baddr2])
                    blra = self.block_analyses[baddr1]
                    if baddr1 == baddr2:
                        moved = "no"
                    else:
                        moved = baddr2
                    md5eq = "yes" if blra.is_md5_equal else "no"
                    if md5eq == "no":
                        if blra.b1len != blra.b2len:
                            instrs_changed = len(blra.instrs_changed(callees))
                            insch = (
                                str(blra.b1len)
                                + " -> "
                                + str(blra.b2len)
                                + " ("
                                + str(instrs_changed)
                                + ")")
                        else:
                            instrs_changed = len(blra.instrs_changed(callees))
                            instrcount = len(blra.b1.instructions)
                            insch = str(instrs_changed) + "/" + str(instrcount)
                    else:
                        insch = "-"
                    if md5eq == "no":
                        lines.append(
                            baddr1.ljust(12)
                            + moved.ljust(16)
                            + md5eq.ljust(18)
                            + insch.ljust(20))
                else:
                    lines.append(baddr1)
            blocksmatched = len(cfgmatcher.blockmapping)
            blocks1 = len(self.basic_blocks1)
            edgesmatched = len(cfgmatcher.edgemapping)
            edges1 = len(cfgmatcher.edges1)

            if showinstructions:
                if blocksmatched == blocks1 and edgesmatched == edges1:
                    for baddr in self.blocks_changed():
                        blra = self.block_analyses[baddr]
                        if len(blra.instrs_changed(callees)) > 0:
                            lines.append(
                                "\nInstructions changed in block "
                                + baddr
                                + " ("
                                + str(len(blra.instrs_changed(callees)))
                                + "):")
                            lines.append(blra.report(callees))
                            lines.append("")

                else:
                    lines.append(
                        "\nNodes matched: " + str(blocksmatched) + "/" + str(blocks1))
                    lines.append(
                        "Edges matched: " + str(edgesmatched) + "/" + str(edges1))
                    lines.append("")
                    for baddr in self.blocks_changed():
                        blra = self.block_analyses[baddr]
                        if len(blra.instrs_changed(callees)) > 0:
                            lines.append(
                                "\nInstructions changed in block "
                                + baddr
                                + " ("
                                + str(len(blra.instrs_changed(callees)))
                                + "):")
                            lines.append(blra.report(callees))
                            lines.append("")

                lines.append("\n\nCfgs are not isomorphic; performing general cfg matching")
                lines.append("-" * 80)
                lines.append(str(cfgmatcher))

        return "\n".join(lines)
