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
"""Dissects a trampoline and checks the various components."""

from typing import Any, cast, Dict, List, Mapping, Optional, Tuple, TYPE_CHECKING

from chb.jsoninterface.JSONResult import JSONResult
from chb.relational.InstructionRelationalAnalysis import (
    InstructionRelationalAnalysis)

import chb.relational.relationalutil as UR
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.BasicBlock import BasicBlock
    from chb.app.Cfg import Cfg
    from chb.app.Instruction import Instruction
    from chb.arm.ARMInstruction import ARMInstruction
    from chb.relational.CfgMatcher import CfgMatcher


class TrampolineAnalysis:

    def __init__(
            self,
            app1: "AppAccess",
            b1: "BasicBlock",
            app2: "AppAccess",
            trampoline: List["BasicBlock"],
            cfgmatcher: "CfgMatcher") -> None:
        self._app1 = app1
        self._app2 = app2
        self._b1 = b1
        self._trampoline = trampoline
        self._cfgmatcher = cfgmatcher
        self._instrmapping: Dict[str, str] = {}
        self._revinstrmapping: Dict[str, str] = {}
        self._instranalyses: Dict[str, InstructionRelationalAnalysis] = {}
        self._distance: int = -1
        self._roles: Optional[Dict[str, str]] = None

    @property
    def app1(self) -> "AppAccess":
        return self._app1

    @property
    def app2(self) -> "AppAccess":
        return self._app2

    @property
    def cfgmatcher(self) -> "CfgMatcher":
        return self._cfgmatcher

    @property
    def cfg2(self) -> "Cfg":
        return self.cfgmatcher.cfg2

    @property
    def b1(self) -> "BasicBlock":
        return self._b1

    @property
    def trampoline(self) -> List["BasicBlock"]:
        return self._trampoline

    @property
    def roles(self) -> Dict[str, str]:
        if self._roles is None:
            self._roles = {}
            (s1, s2) = self.spliced_blocks
            self._roles[s1.baddr] = "split-block-pre"
            self._roles[s2.baddr] = "split-block-post"
            self._roles[self.trampoline_setup] = "trampoline-setup"
            self._roles[self.trampoline_takedown] = "trampoline-takedown"

            if self.trampoline_structure == "breakout":
                self._roles[self.trampoline_payload] = "trampoline-payload"
                self._roles[self.trampoline_decision] = "trampoline-decision"
                self._roles[self.trampoline_breakout] = "trampoline-breakout"
            elif self.trampoline_structure == "alternate-action":
                self._roles[
                    self.trampoline_payload_check] = "trampoline-payload:check"
                self._roles[
                    self.trampoline_payload_conditional_action] = (
                        "trampoline-payload:conditional-action")
                self._roles[
                    self.trampoline_payload_skip_action] = (
                        "trampoline-payload:skip-action")
            else:
                for b in self.trampoline:
                    if b.baddr not in self._roles:
                        self._roles[b.baddr] = "trampoline:unknown"
        return self._roles

    @property
    def distance(self) -> int:
        return self._distance

    @property
    def spliced_blocks(self) -> Tuple["BasicBlock", "BasicBlock"]:
        firstblock: Optional["BasicBlock"] = None
        lastblock: Optional["BasicBlock"] = None
        for b2 in self.trampoline:
            if b2.baddr == self.b1.baddr:
                firstblock = b2
            elif b2.lastaddr == self.b1.lastaddr:
                lastblock = b2
        if firstblock is None or lastblock is None:
            raise UF.CHBError("No spliced blocks found")
        return (firstblock, lastblock)

    @property
    def trampoline_structure(self) -> str:
        payloadsize: int = 0
        for b in self.trampoline:
            if b.baddr.startswith("F"):
                payloadsize += 1
        if payloadsize == 1:
            return "breakout"
        elif payloadsize == 3:
            return "alternate-action"
        else:
            return "unknown"

    @property
    def trampoline_setup(self) -> str:
        (s2start, s2end) = self.spliced_blocks
        if s2start.baddr in self.cfg2.edges:
            if len(self.cfg2.edges[s2start.baddr]) == 1:
                return self.cfg2.edges[s2start.baddr][0]
        raise UF.CHBError("No setup block found")

    @property
    def trampoline_setup_block(self) -> "BasicBlock":
        addr = self.trampoline_setup
        for b in self.trampoline:
            if b.baddr == addr:
                return b
        raise UF.CHBError("Trampoline setup block not found")

    @property
    def trampoline_payload(self) -> str:
        setup = self.trampoline_setup
        if setup in self.cfg2.edges:
            if len(self.cfg2.edges[setup]) == 1:
                return self.cfg2.edges[setup][0]
        raise UF.CHBError("No trampoline payload found")

    @property
    def trampoline_payload_block(self) -> "BasicBlock":
        addr = self.trampoline_payload
        for b in self.trampoline:
            if b.baddr == addr:
                return b
        raise UF.CHBError("Trampoline payload block not found")

    @property
    def trampoline_payload_check(self) -> str:
        setup = self.trampoline_setup
        if setup in self.cfg2.edges:
            if len(self.cfg2.edges[setup]) == 1:
                return self.cfg2.edges[setup][0]
        raise UF.CHBError("No trampoline payload:check found")

    @property
    def trampoline_payload_check_block(self) -> "BasicBlock":
        addr = self.trampoline_payload_check
        for b in self.trampoline:
            if b.baddr == addr:
                return b
        raise UF.CHBError("Trampoline payload check block not found")

    @property
    def trampoline_payload_skip_action(self) -> str:
        check = self.trampoline_payload_check
        if check in self.cfg2.edges:
            if len(self.cfg2.edges[check]) == 2:
                return self.cfg2.edges[check][0]
        raise UF.CHBError("No trampoline payload:skip-action found")

    @property
    def trampoline_payload_skip_action_block(self) -> "BasicBlock":
        addr = self.trampoline_payload_skip_action
        for b in self.trampoline:
            if b.baddr == addr:
                return b
        raise UF.CHBError("Trampoline payload:skip-action block not found")

    @property
    def trampoline_payload_conditional_action(self) -> str:
        check = self.trampoline_payload_check
        if check in self.cfg2.edges:
            if len(self.cfg2.edges[check]) == 2:
                return self.cfg2.edges[check][1]
        raise UF.CHBError("No trampoline payload:conditional_action found")

    @property
    def trampoline_payload_conditional_action_block(self) -> "BasicBlock":
        addr = self.trampoline_payload_conditional_action
        for b in self.trampoline:
            if b.baddr == addr:
                return b
        raise UF.CHBError("Trampoline payload:conditional-action block not found")

    @property
    def trampoline_decision(self) -> str:
        tf = self.trampoline_payload
        if tf in self.cfg2.edges:
            if len(self.cfg2.edges[tf]) == 1:
                return self.cfg2.edges[tf][0]
        raise UF.CHBError("No trampoline decision block found")

    @property
    def trampoline_takedown(self) -> str:
        (s2start, s2end) = self.spliced_blocks
        if self.trampoline_structure == "breakout":
            td = self.trampoline_decision
            if td in self.cfg2.edges:
                for succ in self.cfg2.edges[td]:
                    if succ in self.cfg2.edges:
                        if len(self.cfg2.edges[succ]) == 1:
                            if self.cfg2.edges[succ][0] == s2end.baddr:
                                return succ
            raise UF.CHBError(
                "No trampoline takedown block found for breakout trampoline")
        elif self.trampoline_structure == "alternate-action":
            tda = self.trampoline_payload_skip_action
            tdr = self.trampoline_payload_conditional_action
            if tda in self.cfg2.edges and tdr in self.cfg2.edges:
                if len(self.cfg2.edges[tda]) == 1 and len(self.cfg2.edges[tdr]) == 1:
                    if self.cfg2.edges[tda][0] == self.cfg2.edges[tdr][0]:
                        return self.cfg2.edges[tda][0]
            raise UF.CHBError(
                "No trampoline takedown block found for alternate-action trampoline")
        else:
            raise UF.CHBError("No trampoline takedown block found")

    @property
    def trampoline_takedown_block(self) -> "BasicBlock":
        addr = self.trampoline_takedown
        for b in self.trampoline:
            if b.baddr == addr:
                return b
        raise UF.CHBError("Trampoline takedown block not found")

    @property
    def trampoline_breakout(self) -> str:
        (s2start, s2end) = self.spliced_blocks
        td = self.trampoline_decision
        if td in self.cfg2.edges:
            for succ in self.cfg2.edges[td]:
                if succ == self.trampoline_takedown:
                    continue
                return succ
        raise UF.CHBError("No trampoline breakout block found")

    @property
    def trampoline_breakout_block(self) -> "BasicBlock":
        addr = self.trampoline_breakout
        for b in self.trampoline:
            if b.baddr == addr:
                return b
        raise UF.CHBError("Trampoline breakout block not found")

    def levenshtein_distance(self) -> Tuple[
            int, List[Tuple[Optional[int], Optional[int]]]]:
        (b2start, b2end) = self.spliced_blocks
        s2start = list((i.bytestring for (a, i) in sorted(b2start.instructions.items())))
        s2end = list((i.bytestring for (a, i) in sorted(b2end.instructions.items())))
        s2 = s2start + s2end
        s1 = list((i.bytestring for (a, i) in sorted(self.b1.instructions.items())))
        return UR.levenshtein(s1, s2)

    @property
    def instr_mapping(self) -> Mapping[str, str]:
        if len(self._instrmapping) == 0:
            (dist, mapping) = self.levenshtein_distance()
            self._distance = dist
            self.match_instructions(mapping)
        return self._instrmapping

    @property
    def rev_instr_mapping(self) -> Mapping[str, str]:
        if len(self._revinstrmapping) == 0:
            mapping = self.instr_mapping
        return self._revinstrmapping    

    def match_instructions(
            self, mapping: List[Tuple[Optional[int], Optional[int]]]) -> None:
        b1addrs = sorted(self.b1.instructions.keys())
        (b2start, b2end) = self.spliced_blocks
        b2startaddrs = sorted(b2start.instructions.keys())
        b2endaddrs = sorted(b2end.instructions.keys())
        b2addrs = b2startaddrs + b2endaddrs
        for (x, y) in mapping:
            if x is not None and y is not None:
                self._instrmapping[b1addrs[x]] = b2addrs[y]
                self._revinstrmapping[b2addrs[y]] = b1addrs[x]

    @property
    def instr_analyses(self) -> Mapping[str, InstructionRelationalAnalysis]:
        (b2start, b2end) = self.spliced_blocks
        if len(self._instranalyses) == 0:
            for iaddr1 in self.b1.instructions:
                if iaddr1 in self.instr_mapping:
                    iaddr2 = self.instr_mapping[iaddr1]
                    if iaddr2 in b2start.instructions:
                        instr2: Optional["Instruction"] = b2start.instructions[iaddr2]
                    elif iaddr2 in b2end.instructions:
                        instr2 = b2end.instructions[iaddr2]
                    else:
                        instr2 = None
                    self._instranalyses[iaddr1] = InstructionRelationalAnalysis(
                        self.app1,
                        self.b1.instructions[iaddr1],
                        self.app2,
                        instr2)
                else:
                    self._instranalyses[iaddr1] = InstructionRelationalAnalysis(
                        self.app1,
                        self.b1.instructions[iaddr1],
                        self.app2,
                        None)
        return self._instranalyses

    @property
    def instrs_replaced(self) -> List["Instruction"]:
        result: List["Instruction"] = []
        for (iaddr, ira) in sorted(self.instr_analyses.items()):
            if (
                    not ira.is_md5_equal
                    or ira.has_different_annotation
                    or (not ira.same_address)):
                result.append(ira.instr1)
        return result

    def setup_restore_context_comparison(
            self, setup: "Instruction", restore: "Instruction") -> str:

        lines: List[str] = []
        if setup.mnemonic.startswith("PUSH") and restore.mnemonic.startswith("POP"):
            pushassigns = list(zip(setup.xdata.vars, setup.xdata.xprs[2:]))
            popassigns = list(zip(restore.xdata.vars, restore.xdata.xprs[2:]))

            lines.append(
                (" " * 16)
                + "Save context".ljust(32)
                + "Restore context")
            lines.append("-" * 80)
            lines.append(
                "iaddr".ljust(16)
                + setup.real_iaddr.ljust(16)
                + restore.real_iaddr.ljust(16))
            lines.append(
                "SP before".ljust(16)
                + str(setup.stackpointer_offset.offsetvalue()).ljust(32)
                + str(restore.stackpointer_offset.offsetvalue()).ljust(32))
            lines.append(
                "opcode".ljust(16)
            + setup.mnemonic.ljust(32)
                + restore.mnemonic)
            spsetup = pushassigns[0][1]
            sprestore = popassigns[0][1]
            lines.append(
                "SP after".ljust(16)
                + str(spsetup.stack_address_offset()).ljust(32)
                + str(sprestore.stack_address_offset()).ljust(32))
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

    def report(self, callees: List[str] = []) -> str:
        lines: List[str] = []
        for iaddr in sorted(self.instr_analyses):
            ira = self.instr_analyses[iaddr]
            if (
                    not ira.is_md5_equal
                    or ira.has_different_annotation
                    or (not ira.same_address)):

                if ira.is_mapped:
                    moved = "" if ira.same_address else " (moved)"
                    b1 = ira.instr1.bytestring
                    b2 = ira.instr2.bytestring
                    lines.append(
                        "  V:"
                        + ira.instr1.iaddr
                        + "  "
                        + b1.ljust(8)
                        + "  "
                        + str(ira.instr1))
                    lines.append(
                        "  P:"
                        + ira.instr2.iaddr
                        + "  "
                        + b2.ljust(8)
                        + "  "
                        + str(ira.instr2)
                        + moved)
                    lines.append("")

                else:
                    b1 = ira.instr1.bytestring
                    lines.append(
                        "  V:"
                        + ira.instr1.iaddr
                        + "  "
                        + b1.ljust(8)
                        + "  "
                        + str(ira.instr1))
                    lines.append("  P: not mapped")
                    lines.append("")

        try:
            lines.append("\nTrampoline components:")
            lines.append("  setup   : " + self.trampoline_setup)
            lines.append("  takedown: " + self.trampoline_takedown)

            if self.trampoline_structure == "breakout":
                lines.append("  payload : " + self.trampoline_payload_block.real_baddr)
                lines.append("  decision: " + self.trampoline_decision)
                lines.append("  breakout: " + self.trampoline_breakout)
            elif self.trampoline_structure == "alternate-action":
                lines.append(
                    "  payload:check             : "
                    + self.trampoline_payload_check_block.real_baddr)
                lines.append(
                    "  payload:conditional-action: "
                    + self.trampoline_payload_conditional_action_block.real_baddr)
                lines.append(
                    "  payload:skip-action       : "
                    + self.trampoline_payload_skip_action_block.real_baddr)
        except UF.CHBError as e:
            lines.append("")
            lines.append("*" * 80)
            lines.append("* Error encountered in dissecting trampoline:")
            lines.append("*   " + str(e))
            lines.append("*" * 80)
            return "\n".join(lines)

        if self.trampoline_structure == "breakout":
            trfun = self.trampoline_payload_block
            (iaddr, chkinstr) = sorted(trfun.instructions.items())[-2]
            chkinstr = cast("ARMInstruction", chkinstr)
            condition: str = "?"
            if chkinstr.mnemonic_stem == "MOV":
                if chkinstr.has_instruction_condition():
                    condition = str(chkinstr.get_instruction_condition())
            lines.append("\nTrampoline breakout check performed: " + str(condition))
            lines.append("")

        elif self.trampoline_structure == "alternate-action":
            trfun = self.trampoline_payload_check_block
            (iaddr, chkinstr) = sorted(trfun.instructions.items())[-1]
            chkinstr = cast("ARMInstruction", chkinstr)

            condition = "?"
            if chkinstr.mnemonic_stem == "CBZ":
                if chkinstr.xdata.has_branch_conditions():
                    condition = str(chkinstr.xdata.get_branch_conditions()[3])
            lines.append("\nTrampoline check inserted: " + str(condition))
            lines.append("If check is true:")
            cinstrs = self.trampoline_payload_conditional_action_block.instructions
            for iaddr in sorted(cinstrs)[:-2]:
                ci = cinstrs[iaddr]
                lines.append("   " + ci.real_iaddr + "  " + str(ci))
            skipinstrs = self.trampoline_payload_skip_action_block.instructions
            if len(skipinstrs) <= 2:
                lines.append("\nElse: skip")
            else:
                lines.append("\nElse:")
                for iaddr in sorted(skipinstrs):
                    ci = skipinstrs[iaddr]
                    lines.append("  " + ci.real_iaddr + "  " + str(ci))

        else:
            lines.append("\nNo Trampoline check condition recognized")

        replaced = self.instrs_replaced
        trinstrs = sorted(self.trampoline_takedown_block.instructions.items())
        restoreinstrs = [i[1] for i in trinstrs[1:-1]]
        if len(replaced) == len(restoreinstrs):
            lines.append("\nComparison of instructions replaced and restored")
            for (i1, i2) in zip(replaced, restoreinstrs):
                lines.append("replaced:  " + i1.iaddr + "  " + str(i1))
                lines.append("restored:  " + i2.iaddr + "  " + str(i2))
                lines.append("")

        elif len(replaced) > len(restoreinstrs):
            sreplaced = list(i.bytestring for i in sorted(replaced, key=lambda i:i.iaddr))
            srestored = list(i.bytestring for i in restoreinstrs)
            (d, splice) = UR.levenshtein(sreplaced, srestored)
            lines.append("\nInstructions restored in takedown block:")
            for (x, y) in splice:
                if (x is not None) and (y is not None):
                    xinstr = replaced[x]
                    yinstr = restoreinstrs[y]
                    lines.append("  " + xinstr.real_iaddr + "  " + str(xinstr))
                    lines.append("  " + yinstr.real_iaddr + "  " + str(yinstr))
                    lines.append("")

            lines.append("Instructions not restored (captured by conditional):")
            for (x, y) in sorted(splice):
                if (x is not None) and (y is None):
                    xinstr = replaced[x]
                    lines.append("  " + xinstr.real_iaddr + "  " + str(xinstr))
        else:
            lines.append("\nNo comparison yet")

        setupinstrs = sorted(self.trampoline_setup_block.instructions.items())
        i1 = setupinstrs[0][1]
        takedowninstrs = sorted(self.trampoline_takedown_block.instructions.items())
        i2 = takedowninstrs[0][1]

        lines.append(
            "\n\nComparison of context stored (in setup) and context restored (in takedown)")
        lines.append(self.setup_restore_context_comparison(i1, i2))

        return "\n".join(lines)
