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
    Any, cast, Dict, List, Mapping, Optional, Set, Tuple, TYPE_CHECKING,
)

from chb.jsoninterface.JSONResult import JSONResult
from chb.relational.BlockRelationalAnalysis import BlockRelationalAnalysis
from chb.relational.CfgMatcher import CfgMatcher

from chb.util.loggingutil import chklogger


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
        self._blockinfo: Optional[Dict[str, int]] = None

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
    def name1(self) -> Optional[str]:
        if self.app1.has_function_name(self.faddr1):
            return self.app1.function_name(self.faddr1) + " (" + self.faddr1 + ")"
        return None

    @property
    def name2(self) -> Optional[str]:
        if self.app2.has_function_name(self.faddr1):
            return self.app2.function_name(self.faddr2) + " (" + self.faddr2 + ")"
        return None

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
                    chklogger.logger.warning(
                        "Error in mapping returned from cfg matcher of %s (%s) "
                        + "and %s (%s): %s",
                        self.faddr1,
                        str(len(self.basic_blocks1)),
                        self.faddr2,
                        str(len(self.basic_blocks2)),
                        str(e))

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
            else:
                trampoline_minimal_pair_2_and_3 = self.has_minimal_pair_2_and_3_trampoline()
                if trampoline_minimal_pair_2_and_3 is not None:
                    self.setup_minimal_pair_2_and_3_trampoline_analysis(
                        trampoline_minimal_pair_2_and_3)

        return self._blockanalyses

    def setup_trampoline_analysis(self, b: str) -> None:
        cfg1unmapped = self.cfgmatcher.unmapped_blocks1
        cfg2unmapped = [
            b for b in self.cfgmatcher.unmapped_blocks2 if b in self.cfgtc_blocks2]
        if (b in cfg2unmapped):
            trampoline = cast("ARMCfgTrampolineBlock", self.cfgtc_blocks2[b])
            tpre = trampoline.prenodes
            tpost = trampoline.postnodes
            # Need this definition up here, otherwise mypy gets mad.
            roles: Dict[str, "BasicBlock"] = {}

            if len(tpre) == 1 and len(tpost) == 1:
                if (
                        tpre[0] in cfg2unmapped
                        and tpost[0] in cfg2unmapped
                        and tpre[0] in cfg1unmapped):
                    # Case where trampoline has an early return and a fallthrough case
                    # (what we mark as the exit block)
                    roles["entry"] = self.basic_blocks2[tpre[0]]
                    roles["exit"] = self.basic_blocks2[tpost[0]]
                    for (role, addr) in trampoline.roles.items():
                        roles[role] = self.basic_blocks2[addr]
                    self._blockanalyses[tpre[0]] = BlockRelationalAnalysis(
                        self.app1,
                        self.basic_blocks1[tpre[0]],
                        self.app2,
                        roles)
                else:
                    chklogger.logger.warning("Found unhandled trampoline case. Should be an early return "
                                             "trampoline (pre %s, post %s), but the blocks are not "
                                             "in the unmapped lists. cfg1: %s, cfg2: %s",
                                             tpre[0], tpost[0], cfg1unmapped, cfg2unmapped)
            elif len(tpre) == 1 and len(tpost) == 2:
                # Trampoline has a continue statement.
                # One of the post blocks is the fallthrough/exit, one is the loop continuation.
                # Need to figure out which one is which
                if not 'continuepath' in trampoline.roles:
                    chklogger.logger.error("Found unsupported trampoline case, "
                                           "There are 2 post trampoline blocks %s but no continuepath role %s",
                                           tpost, trampoline.roles)
                    return

                cont = self.basic_blocks2[trampoline.roles['continuepath']]
                cont_post = self.cfg2.edges[cont.baddr]
                if len(cont_post) != 1:
                    chklogger.logger.error("Found unsupported trampoline case, "
                                           "continue block %s has more than one outgoing edges: %s",
                                           cont.baddr, cont_post)
                    return
                fallthrough = self.basic_blocks2[trampoline.roles['fallthrough']]
                fallthrough_post = self.cfg2.edges[fallthrough.baddr]
                if len(fallthrough_post) != 1:
                    chklogger.logger.error("Found unsupported trampoline case, "
                                           "fallthrough block %s has more than one outgoing edges: %s",
                                           fallthrough.baddr, fallthrough_post)
                    return

                roles["entry"] = self.basic_blocks2[tpre[0]]
                roles["exit"] = self.basic_blocks2[fallthrough_post[0]]
                for (role, addr) in trampoline.roles.items():
                    roles[role] = self.basic_blocks2[addr]
                self._blockanalyses[tpre[0]] = BlockRelationalAnalysis(
                    self.app1,
                    self.basic_blocks1[tpre[0]],
                    self.app2,
                    roles)
            else:
                    chklogger.logger.warning("Found unhandled trampoline case. Have %d pre-blocks "
                                             "%d post-blocks. pre: %s, post %s",
                                             len(tpre), len(tpost), tpre, tpost)

    def setup_minimal_pair_2_and_3_trampoline_analysis(self, b: str) -> None:
        chklogger.logger.info("Setup minimal_pair_2_and_3_trampoline at %s", b)
        cfg1unmapped = self.cfgmatcher.unmapped_blocks1
        cfg2unmapped = [
            b for b in self.cfgmatcher.unmapped_blocks2 if b in self.cfgtc_blocks2]
        if (b in cfg2unmapped):
            trampoline = cast("ARMCfgTrampolineBlock", self.cfgtc_blocks2[b])
            tpre = trampoline.prenodes
            tpost = trampoline.postnodes
            if len(tpre) == 1 and len (tpost) == 1:
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

    def has_minimal_pair_2_and_3_trampoline(self) -> Optional[str]:
        for (b, cfgb) in self.cfgtc_blocks2.items():
            if cfgb.is_trampoline_minimal_pair_2_and_3:
                return b
        return None

    def blocks_changed(self) -> List[str]:
        """Return a list of block addresses that are not md5-equal."""

        result: List[str] = []
        for baddr in self.block_analyses:
            if not self.block_analyses[baddr].is_md5_equal:
                result.append(baddr)
        return result

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

    def to_json_result(self, callees: List[str]) -> JSONResult:
        schema = "functioncomparison"
        content: Dict[str, Any] = {}
        content["faddr1"] = self.faddr1
        content["faddr2"] = self.faddr2
        if self.name1:
            content["name1"] = self.name1
        if self.name2:
            content["name2"] = self.name2

        cfg1 = self.fn1.to_json_result()
        if not cfg1.is_ok:
            return JSONResult(schema, {}, "fail", cfg1.reason)

        content["cfg1"] = cfg1.content

        cfg2 = self.fn2.to_json_result()
        if not cfg2.is_ok:
            return JSONResult(schema, {}, "fail", cfg2.reason)

        content["cfg2"] = cfg2.content

        changes: List[str] = []
        blockmapping: List[Dict[str, Any]] = []

        for (baddr1, blockra) in self.block_analyses.items():
            blockmap = blockra.to_json_result(callees)
            if not blockmap.is_ok:
                return JSONResult(schema, {}, "fail", blockmap.reason)
            blockmapping.append(blockmap.content)

        content["cfg-block-mapping"] = blockmapping

        blockschanged: List[str] = []
        fblockschanged = self.blocks_changed()
        if len(fblockschanged) > 0:
            changes.append("blocks")
            blockschanged.extend(fblockschanged)
            content["blocks-changed"] = blockschanged
        content["changes"] = self.changes
        content["matches"] = self.matches
        return JSONResult(schema, content, "ok")
