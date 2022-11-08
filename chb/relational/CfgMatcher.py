# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs, LLC
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
"""Creates a mapping of basic blocks and edges between two executables."""

from typing import Dict, List, Mapping, Set, Tuple, TYPE_CHECKING

from chb.graphics.DotCfg import DotCfg

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.BasicBlock import BasicBlock
    from chb.app.Cfg import Cfg
    from chb.app.Function import Function


class CfgMatcher:

    def __init__(
            self,
            app1: "AppAccess",
            fn1: "Function",
            cfg1: "Cfg",
            app2: "AppAccess",
            fn2: "Function",
            cfg2: "Cfg",
            blockmapping: Dict[str, str],
            edgemapping: Dict[Tuple[str, str], Tuple[str, str]]) -> None:
        self._app1 = app1
        self._app2 = app2
        self._fn1 = fn1
        self._fn2 = fn2
        self._cfg1 = cfg1
        self._cfg2 = cfg2
        self._src1map: Dict[str, List[str]] = {}
        self._src2map: Dict[str, List[str]] = {}
        self._tgt1map: Dict[str, List[str]] = {}
        self._tgt2map: Dict[str, List[str]] = {}
        self._blockmapping = blockmapping
        self._edgemapping = edgemapping
        self._blockmd5s: Dict[str, Tuple[List[str], List[str]]] = {}
        self._blockstrings: Dict[str, Tuple[List[str], List[str]]] = {}
        self._blockcalls: Dict[str, Tuple[List[str], List[str]]] = {}
        self._blockbranches: Dict[str, Tuple[List[str], List[str]]] = {}
        self._unmapped_blocks1: List[str] = []
        self._unmapped_blocks2: List[str] = []
        self._multiple_mapping: List[Tuple[List[str], List[str]]] = []
        self.match()

    @property
    def app1(self) -> "AppAccess":
        return self._app1

    @property
    def app2(self) -> "AppAccess":
        return self._app2

    @property
    def fn1(self) -> "Function":
        return self._fn1

    @property
    def fn2(self) -> "Function":
        return self._fn2

    @property
    def cfg1(self) -> "Cfg":
        return self._cfg1

    @property
    def cfg2(self) -> "Cfg":
        return self._cfg2

    @property
    def basic_blocks1(self) -> Mapping[str, "BasicBlock"]:
        return self.fn1.blocks

    @property
    def basic_blocks2(self) -> Mapping[str, "BasicBlock"]:
        return self.fn2.blocks

    @property
    def edges1(self) -> Set[Tuple[str, str]]:
        return self.cfg1.edges_as_set

    @property
    def edges2(self) -> Set[Tuple[str, str]]:
        return self.cfg2.edges_as_set

    @property
    def blockmapping(self) -> Dict[str, str]:
        return self._blockmapping

    @property
    def edgemapping(self) -> Dict[Tuple[str, str], Tuple[str, str]]:
        return self._edgemapping

    @property
    def unmapped_blocks1(self) -> List[str]:
        return self._unmapped_blocks1

    @property
    def unmapped_blocks2(self) -> List[str]:
        return self._unmapped_blocks2

    @property
    def same_endianness(self) -> bool:
        return self.app1.header.is_big_endian == self.app2.header.is_big_endian

    def src1post(self, src1) -> List[str]:
        if src1 in self._src1map:
            return self._src1map[src1]
        else:
            return []

    def src2post(self, src2) -> List[str]:
        if src2 in self._src2map:
            return self._src2map[src2]
        else:
            return []

    def tgt1pre(self, tgt1) -> List[str]:
        if tgt1 in self._tgt1map:
            return self._tgt1map[tgt1]
        else:
            return []

    def tgt2pre(self, tgt2) -> List[str]:
        if tgt2 in self._tgt2map:
            return self._tgt2map[tgt2]
        else:
            return []

    def initialize(self) -> None:
        for (e1, e2) in self.edges1:
            self._src1map.setdefault(e1, [])
            self._src1map[e1].append(e2)
            self._tgt1map.setdefault(e2, [])
            self._tgt1map[e2].append(e1)

        for (e1, e2) in self.edges2:
            self._src2map.setdefault(e1, [])
            self._src2map[e1].append(e2)
            self._tgt2map.setdefault(e2, [])
            self._tgt2map[e2].append(e1)

    @property
    def is_cfg_isomorphic(self) -> bool:
        if (
                self.cfg1.is_reducible
                and self.cfg2.is_reducible
                and len(self.basic_blocks1) == len(self.basic_blocks2)):
            rpo1 = self.cfg1.rpo_sorted_nodes
            rpo2 = self.cfg2.rpo_sorted_nodes
            for (n, m) in zip(rpo1, rpo2):
                self._blockmapping[n] = m
            self.match_edges()
            return len(self.edgemapping) == len(self.edges1)
        else:
            return False

    def match(self) -> None:
        if len(self._blockmapping) > 0:
            return
        elif (
                self.cfg1.is_reducible
                and self.cfg2.is_reducible
                and len(self.basic_blocks1) == len(self.basic_blocks2)):
            rpo1 = self.cfg1.rpo_sorted_nodes
            rpo2 = self.cfg2.rpo_sorted_nodes
            for (n, m) in zip(rpo1, rpo2):
                self._blockmapping[n] = m
            self.match_edges()
        else:
            self.initialize()
            self.collect_blockmd5s()
            self.match_blockmd5s()
            self.collect_blockstrings()
            self.match_blockstrings()
            self.collect_blockcalls()
            self.match_blockcalls()
            self.collect_branch_conditions()
            self.match_branch_conditions()
            self.match_edges()
            self.propagate_post()
            self.propagate_pre()

    def collect_blockmd5s(self) -> None:
        for (baddr, b1) in self.basic_blocks1.items():
            md5 = b1.md5()
            self._blockmd5s.setdefault(md5, ([], []))
            self._blockmd5s[md5][0].append(baddr)
        for (baddr, b2) in self.basic_blocks2.items():
            if self.same_endianness:
                md5 = b2.md5()
            else:
                md5 = b2.rev_md5()
            self._blockmd5s.setdefault(md5, ([], []))
            self._blockmd5s[md5][1].append(baddr)

    def collect_blockstrings(self) -> None:
        for (baddr, b1) in self.basic_blocks1.items():
            for instr1 in b1.instructions.values():
                s1 = instr1.string_pointer_loaded()
                if s1:
                    self._blockstrings.setdefault(s1[0], ([], []))
                    self._blockstrings[s1[0]][0].append(baddr)
        for (baddr, b2) in self.basic_blocks2.items():
            for instr2 in b2.instructions.values():
                s2 = instr2.string_pointer_loaded()
                if s2:
                    self._blockstrings.setdefault(s2[0], ([], []))
                    self._blockstrings[s2[0]][1].append(baddr)

    def collect_blockcalls(self) -> None:
        for (baddr, b1) in self.basic_blocks1.items():
            for instr1 in b1.instructions.values():
                if instr1.is_call_instruction:
                    ann = instr1.annotation
                    self._blockcalls.setdefault(ann, ([], []))
                    self._blockcalls[ann][0].append(baddr)
        for (baddr, b2) in self.basic_blocks2.items():
            for instr2 in b2.instructions.values():
                if instr2.is_call_instruction:
                    ann = instr2.annotation
                    self._blockcalls.setdefault(ann, ([], []))
                    self._blockcalls[ann][1].append(baddr)

    def collect_branch_conditions(self) -> None:
        for (baddr, b1) in self.basic_blocks1.items():
            for instr1 in b1.instructions.values():
                if instr1.is_branch_instruction:
                    ft = instr1.ft_conditions
                    if len(ft) == 2:
                        bc = str(ft[1])
                        self._blockbranches.setdefault(bc, ([], []))
                        self._blockbranches[bc][0].append(baddr)
        for (baddr, b2) in self.basic_blocks2.items():
            for instr2 in b2.instructions.values():
                if instr2.is_branch_instruction:
                    ft = instr2.ft_conditions
                    if len(ft) == 2:
                        bc = str(ft[1])
                        self._blockbranches.setdefault(bc, ([], []))
                        self._blockbranches[bc][1].append(baddr)

    def match_blockmd5s(self) -> None:
        for (b1s, b2s) in self._blockmd5s.values():
            if len(b1s) == 1 and len(b2s) == 1:
                self._blockmapping[b1s[0]] = b2s[0]
            elif len(b1s) == 1 and len(b2s) == 0:
                self._unmapped_blocks1.append(b1s[0])
            elif len(b1s) == 0 and len(b2s) == 1:
                self._unmapped_blocks2.append(b2s[0])
            else:
                self._multiple_mapping.append((b1s, b2s))

    def match_blockstrings(self) -> None:
        for (s, (b1s, b2s)) in self._blockstrings.items():
            if len(b1s) == 1 and len(b2s) == 1:
                b1 = b1s[0]
                b2 = b2s[0]
                if b1 not in self.blockmapping:
                    self._blockmapping[b1] = b2
                elif self.blockmapping[b1] != b2:
                    print("Conflicting mapping: " + b1 + ", " + b2)

    def match_blockcalls(self) -> None:
        for (s, (b1s, b2s)) in self._blockcalls.items():
            if len(b1s) == 1 and len(b2s) == 1:
                b1 = b1s[0]
                b2 = b2s[0]
                if b1 not in self.blockmapping:
                    self._blockmapping[b1] = b2
                elif self.blockmapping[b1] != b2:
                    print("Conflicting mapping: " + b1 + ", " + b2)

    def match_branch_conditions(self) -> None:
        for (s, (b1s, b2s)) in self._blockbranches.items():
            if len(b1s) == 1 and len(b2s) == 1:
                b1 = b1s[0]
                b2 = b2s[0]
                if b1 not in self.blockmapping:
                    self._blockmapping[b1] = b2
                elif self.blockmapping[b1] != b2:
                    print("Conflicting mapping: " + b1 + ", " + b2)

    def match_edges(self) -> None:

        def nolog(s: str) -> None:
            pass

        for (src1, tgt1) in self.edges1:
            if (src1, tgt1) in self.edgemapping:
                continue
            if src1 in self.blockmapping and tgt1 in self.blockmapping:
                src1m = self.blockmapping[src1]
                tgt1m = self.blockmapping[tgt1]
                if (src1m, tgt1m) in self.edges2:
                    self._edgemapping[(src1, tgt1)] = (src1m, tgt1m)
                else:
                    nolog(
                        "Edge ("
                        + src1m
                        + ", "
                        + tgt1m
                        + ") not found as match for ("
                        + src1
                        + ", "
                        + tgt1
                        + ")")

    def unmatched_edges(self) -> List[Tuple[str, str]]:
        result: List[Tuple[str, str]] = []
        for (s2, t2) in self.edges2:
            if (s2, t2) not in self.edges1:
                result.append((s2, t2))
        return result

    def propagate_post(self) -> None:
        for src1 in sorted(self.basic_blocks1):
            if src1 in self.blockmapping:
                src2 = self.blockmapping[src1]
                tgts1 = self.src1post(src1)
                tgts2 = self.src2post(src2)
                if len(tgts1) == len(tgts2):
                    if len(tgts1) == 1 and tgts1[0] not in self.blockmapping:
                        self._blockmapping[tgts1[0]] = tgts2[0]
                        self._edgemapping[(src1, tgts1[0])] = (src2, tgts2[0])
                    elif (len(tgts1) == 2
                          and tgts1[0] in self.blockmapping
                          and tgts1[1] not in self.blockmapping):
                        if self.blockmapping[tgts1[0]] == tgts2[0]:
                            self._blockmapping[tgts1[1]] = tgts2[1]
                            self._edgemapping[(src1, tgts1[1])] = (src2, tgts2[1])

    def propagate_pre(self) -> None:
        for tgt1 in sorted(self.basic_blocks1, reverse=True):
            if tgt1 in self.blockmapping:
                tgt2 = self.blockmapping[tgt1]
                srcs1 = self.tgt1pre(tgt1)
                srcs2 = self.tgt2pre(tgt2)
                if len(srcs1) == len(srcs2):
                    if len(srcs1) == 1 and srcs1[0] not in self.blockmapping:
                        self._blockmapping[srcs1[0]] = srcs2[0]
                        self._edgemapping[(srcs1[0], tgt1)] = (srcs2[0], tgt2)

    def dot_cfgs(
            self,
            showcalls: bool = False,
            showpredicates: bool = False) -> Tuple[DotCfg, DotCfg]:
        cfg1 = self.cfg1
        cfg2 = self.cfg2
        unmapped1 = self.unmapped_blocks1
        unmapped2 = self.unmapped_blocks2
        colors1: Dict[str, str] = {}
        colors2: Dict[str, str] = {}
        for n in unmapped1:
            colors1[n] = "#FFA500"
        for n in unmapped2:
            colors2[n] = "#FFA500"
        fn1invs = self.fn1.invariants
        fn2invs = self.fn2.invariants
        for b in self.fn1.blocks:
            if b in fn1invs:
                if any(k.is_unreachable for k in fn1invs[b]):
                    colors1[b] = "grey"
        for b in self.fn2.blocks:
            if b in fn2invs:
                if any(k.is_unreachable for k in fn2invs[b]):
                    colors2[b] = "grey"
        dotcfg1 = DotCfg(
            "vulnerable",
            self.fn1,
            nodecolors=colors1,
            showcalls=showcalls,
            showpredicates=showpredicates,
            subgraph=True)
        dotcfg2 = DotCfg(
            "patched",
            self.fn2,
            nodecolors=colors2,
            subgraph=True,
            showcalls=showcalls,
            showpredicates=showpredicates,
            nodeprefix="P")
        return (dotcfg1, dotcfg2)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Block mapping (" + str(len(self.blockmapping)) + ")")
        for (b1, b2) in sorted(self.blockmapping.items()):
            lines.append("  " + b1.ljust(10) + "-- " + b2.ljust(10))
        if len(self.unmapped_blocks1) > 0:
            lines.append(
                "Unmapped blocks original (" + str(len(self.unmapped_blocks1)) + ")")
            for b in sorted(self.unmapped_blocks1):
                lines.append("  " + b)
        if len(self.unmapped_blocks2) > 0:
            lines.append(
                "Unmapped blocks patched (" + str(len(self.unmapped_blocks2)) + ")")
            for b in sorted(self.unmapped_blocks2):
                lines.append("  " + b)
        if len(self.edgemapping) > 0:
            lines.append(
                "\nEdge mapping ("
                + str(len(self.edgemapping))
                + "/"
                + str(len(self.edges1))
                + ")")
            for ((src1, tgt1), (src2, tgt2)) in sorted(self.edgemapping.items()):
                if (src1 + tgt1) != (src2 + tgt2):
                    changed = " (changed)"
                else:
                    changed = ""
                lines.append(
                    "  " + src1 + ", " + tgt1
                    + "  -->  " + src2 + ", " + tgt2 + changed)
        if len(self.unmatched_edges()) > 0:
            lines.append("\nNew edges (" + str(len(self.unmatched_edges())) + ")")
            for (s, t) in self.unmatched_edges():
                lines.append(s + ", " + t)
        return "\n".join(lines)
