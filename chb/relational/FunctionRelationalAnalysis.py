# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs, LLC
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

from typing import (
    Any, cast, Dict, List, Mapping, Optional, Set, Tuple, TYPE_CHECKING)

from chb.jsoninterface.JSONResult import JSONResult
from chb.relational.BlockRelationalAnalysis import BlockRelationalAnalysis
from chb.relational.InstructionRelationalAnalysis import (
    InstructionRelationalAnalysis)
from chb.relational.CfgMatcher import CfgMatcher

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger, LogLevel


if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.BasicBlock import BasicBlock
    from chb.app.Cfg import Cfg
    from chb.app.CfgBlock import CfgBlock
    from chb.app.Function import Function
    from chb.app.Instruction import Instruction
    from chb.arm.ARMCfgBlock import ARMCfgTrampolineBlock
    from chb.arm.ARMFunction import ARMFunction
    from chb.cmdline.PatchResults import PatchEvent


class FunctionRelationalAnalysis:

    def __init__(
            self,
            app1: "AppAccess",
            fn1: "Function",
            app2: "AppAccess",
            fn2: "Function",
            patchevents: Dict[str, "PatchEvent"] = {}) -> None:
        self._app1 = app1
        self._app2 = app2
        self._fn1 = fn1
        self._fn2 = fn2
        self._patchevents = patchevents
        self._cfg1: Optional["Cfg"] = None
        self._cfg2: Optional["Cfg"] = None
        self._cfg2tc: Optional["Cfg"] = None   # trampoline collapsed
        self._cfgblocks1: Mapping[str, "CfgBlock"] = {}
        self._cfgblocks2: Mapping[str, "CfgBlock"] = {}
        self._cfgtcblocks2: Mapping[str, "CfgBlock"] = {}
        self._edges1: Set[Tuple[str, str]] = set([])
        self._edges2: Set[Tuple[str, str]] = set([])
        self._blockmapping: Dict[str, str] = {}
        self._blockanalyses: Dict[str, BlockRelationalAnalysis] = {}
        self._cfgmatcher: Optional[CfgMatcher] = None
        self._changes: Optional[List[str]] = None
        self._matches: Optional[List[str]] = None

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
    def patchevents(self) -> Dict[str, "PatchEvent"]:
        return self._patchevents

    @property
    def offset(self) -> int:
        """Return the difference between the two function addresses."""

        return int(self.faddr2, 16) - int(self.faddr1, 16)

    @property
    def moved(self) -> bool:
        return self.faddr1 != self.faddr2

    @property
    def changes(self) -> List[str]:
        if self._changes is None:
            self._changes = []
            self._matches = []
            if self.faddr1 == self.faddr2:
                self._matches.append("faddr")
            else:
                self._changes.append("faddr")
            if self.is_md5_equal:
                self._matches.append("md5")
            else:
                self._changes.append("md5")
                if len(self.basic_blocks1) == len(self.basic_blocks2):
                    self._matches.append("blockcount")
                else:
                    self._changes.append("blockcount")
                if self.is_automorphic:
                    self._matches.append("cfg-structure")
                else:
                    self._changes.append("cfg-structure")
        return self._changes

    @property
    def matches(self) -> List[str]:
        if self._matches is None:
            changes = self.changes
        if self._matches is None:
            return []
        else:
            return self._matches

    @property
    def same_endianness(self) -> bool:
        return self.app1.header.is_big_endian == self.app2.header.is_big_endian

    def address2_align(self, addr2: str) -> str:
        """Return the corresponding address in fn2 by adding the offset."""

        if addr2.startswith("F") or addr2.startswith("T") or addr2.startswith("P"):
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
    def instructions1(self) -> Mapping[str, "Instruction"]:
        return self.fn1.instructions

    @property
    def instructions2(self) -> Mapping[str, "Instruction"]:
        return self.fn2.instructions

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
    def cfg2tc(self) -> "Cfg":
        """Return a cfg in which the trampoline block is collapsed.

        Currently only available for ARM.
        """

        if not self._cfg2tc:
            fn2 = cast("ARMFunction", self.fn2)
            self._cfg2tc = fn2.cfg_tc(self.patchevents)
        return self._cfg2tc

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
    def cfgtc_blocks2(self) -> Mapping[str, "CfgBlock"]:
        if len(self._cfgtcblocks2) == 0:
            self._cfgtcblocks2 = self.cfg2tc.blocks
        return self._cfgtcblocks2

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
                self.cfg2tc,
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
    def is_automorphic(self) -> bool:
        if self.offset != 0:
            return False
        if len(self.basic_blocks1) != len(self.basic_blocks2):
            return False
        if len(self.edges1) != len(self.edges2):
            return False

        for (b1, b2) in zip(sorted(self.basic_blocks1), sorted(self.basic_blocks2)):
            if b1 != b2:
                return False
        for (e1, e2) in zip(sorted(self.edges1), sorted(self.edges2)):
            if e1 != e2:
                return False
        return True

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
            else:
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
                    {"entry": self.basic_blocks2[b2]}
                )
            trampoline = self.has_trampoline()
            if trampoline is not None:
                self.setup_trampoline_analysis(trampoline)

        return self._blockanalyses

    def setup_trampoline_analysis(self, b: str) -> None:
        cfg1unmapped = self.cfgmatcher.unmapped_blocks1
        cfg2unmapped = [
            b for b in self.cfgmatcher.unmapped_blocks2 if b in self.cfgtc_blocks2]
        if (b in cfg2unmapped):
            trampoline = cast("ARMCfgTrampolineBlock", self.cfgtc_blocks2[b])
            tpre = trampoline.prenodes
            tpost = trampoline.postnodes
            if len(tpre) == 1 and len(tpre) == 1:
                if (
                        tpre[0] in cfg2unmapped
                        and tpost[0] in cfg2unmapped
                        and tpre[0] in cfg1unmapped):
                    roles: Dict[str, "BasicBlock"] = {}
                    roles["entry"] = self.basic_blocks2[tpre[0]]
                    roles["exit"] = self.basic_blocks2[tpost[0]]
                    for (role, addr) in trampoline.roles.items():
                        roles[role] = self.basic_blocks2[addr]
                    self._blockanalyses[tpre[0]] = BlockRelationalAnalysis(
                        self.app1,
                        self.basic_blocks1[tpre[0]],
                        self.app2,
                        roles)

    def has_trampoline(self) -> Optional[str]:
        for (b, cfgb) in self.cfgtc_blocks2.items():
            if cfgb.is_trampoline:
                return b
        return None

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

    def setup_restore_context_comparison(
            self, setup: "Instruction", restore: "Instruction") -> str:

        lines: List[str] = []
        if (
                setup.mnemonic.startswith("PUSH")
                and restore.mnemonic.startswith("POP")):
            pushassigns = list(zip(setup.xdata.vars, setup.xdata.xprs[2:]))
            popassigns = list(zip(restore.xdata.vars, restore.xdata.xprs[2:]))

            lines.append(
                (" " * 16)
                + "Save context".ljust(32)
                + "Restore context")
            lines.append("-" * 80)
            lines.append(
                "iaddr".ljust(16)
                + setup.real_iaddr.ljust(32)
                + restore.real_iaddr.ljust(16))
            if (
                    setup.stackpointer_offset.offset.is_singleton
                    and restore.stackpointer_offset.offset.is_singleton):
                lines.append(
                    "SP before".ljust(16)
                    + str(setup.stackpointer_offset.offsetvalue()).ljust(32)
                    + str(restore.stackpointer_offset.offsetvalue()).ljust(32))
            else:
                chklogger.logger.warning(
                    "Unable to perform setup-restore-context-comparison: "
                    + "Stackpointer at setup or restore not known: "
                    + "setup: %s; restore: %s",
                    str(setup.stackpointer_offset.offset),
                    str(setup.stackpointer_offset.offset))
            lines.append(
                "opcode".ljust(16)
            + setup.mnemonic.ljust(32)
                + restore.mnemonic)
            spsetup = pushassigns[0][1]
            sprestore = popassigns[0][1]
            if spsetup.is_stack_address and sprestore.is_stack_address:
                lines.append(
                    "SP after".ljust(16)
                    + str(spsetup.stack_address_offset()).ljust(32)
                    + str(sprestore.stack_address_offset()).ljust(32))
            else:
                chklogger.logger.warning(
                    "Unable to compare stackpointers: "
                    + "Expression(s) are not stack addresseses: "
                    + "sp at setup: %s; sp at restore: %s",
                    str(spsetup),
                    str(sprestore))
            lines.append("\nregister saves and restores:")
            pushassigns = list(zip(setup.xdata.vars, setup.xdata.xprs[2:]))
            popassigns = list(zip(restore.xdata.vars, restore.xdata.xprs[2:]))
            if len(pushassigns) == len(popassigns):
                for ((v1, a1), (v2, a2)) in zip(pushassigns, popassigns):
                    lines.append(
                        ("  " + str(v2)).ljust(16)
                        + (str(v1) + " = " + str(a1)).ljust(32)
                        + (str(v2) + " = " + str(a2)).ljust(32))

        return "\n".join(lines)

    def to_json_result(self) -> JSONResult:
        schema = "functioncomparison"
        content: Dict[str, Any] = {}
        content["faddr1"] = self.faddr1
        content["faddr2"] = self.faddr2
        content["changes"] = self.changes
        content["matches"] = self.matches

        return JSONResult(schema, content, "ok")

    def report(self, showinstructions: bool, callees: List[str] = []) -> str:
        lines: List[str] = []
        blockheader: List[str] = []
        blockheader.append(
            "block".ljust(12)
            + "moved".ljust(12)
            + "md5-equivalent".ljust(20)
            + "instrs-changed".ljust(20))
        blockheader.append("-" * 80)

        trampolineblock = self.has_trampoline()
        # if self.is_structurally_equivalent:
        if self.is_cfg_isomorphic:
            lines.extend(blockheader)
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

        elif trampolineblock is not None:
            lines.append("\nTrampoline inserted at " + trampolineblock)
            trblock = self.cfgtc_blocks2[trampolineblock]
            lines.append("\nTrampoline components: ")
            for (c, ca) in trblock.roles.items():
                lines.append("  " + c.ljust(30) + ": " + ca)

            setupinstr = self.fn2.instruction(trblock.roles["setupblock"])
            takedowninstr = self.fn2.instruction(trblock.roles["fallthrough"])

            lines.append(
                self.setup_restore_context_comparison(setupinstr, takedowninstr))

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

                lines.append("\n\nCfg Matcher")
                lines.append(str(self.cfgmatcher))


        else:
            cfgmatcher = self.cfgmatcher
            if len(self.instructions1) == len(self.instructions2):
                lines.append("\nInstructions changed")
                lines.append("-" * 80)
                instranalyses: Dict[str, InstructionRelationalAnalysis] = {}
                for ((iaddr1, instr1), (iaddr2, instr2)) in zip(
                        self.instructions1.items(), self.instructions2.items()):
                    if iaddr1 == iaddr2:
                        instranalyses[iaddr1] = InstructionRelationalAnalysis(
                            self.app1, instr1, self.app2, instr2)
                    else:
                        print("Functions don't line up at " + iaddr1 + ", " + iaddr2)
                for (iaddr, ira) in instranalyses.items():
                    if (
                            not ira.is_md5_equal
                            or ira.has_different_annotation
                            or (not ira.same_address)):
                        lines.append(
                            " V:"
                            + ira.instr1.iaddr
                            + "  "
                            + ira.instr1.bytestring.ljust(8)
                            + "  "
                            + str(ira.instr1))
                        lines.append(
                            " P:"
                            + ira.instr2.iaddr
                            + "  "
                            + ira.instr2.bytestring.ljust(8)
                            + "  "
                            + str(ira.instr2))
                        lines.append("")

            else:
                lines.append("not yet supported")

            for baddr1 in sorted(self.basic_blocks1):
                if baddr1 in cfgmatcher.blockmapping:
                    baddr2 = cfgmatcher.blockmapping[baddr1]
                    self._blockanalyses[baddr1] = BlockRelationalAnalysis(
                        self.app1,
                        self.basic_blocks1[baddr1],
                        self.app2,
                        {"entry": self.basic_blocks2[baddr2]})
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
