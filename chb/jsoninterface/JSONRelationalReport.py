# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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
import datetime

from typing import List, Optional

import chb.jsoninterface.JSONAppComparison as AppC
from chb.jsoninterface.JSONAssemblyInstruction import JSONAssemblyInstruction
import chb.jsoninterface.JSONBlockComparison as BlockC
import chb.jsoninterface.JSONFunctionComparison as FunC
import chb.jsoninterface.JSONInstructionComparison as InstrC
from chb.jsoninterface.JSONObjectNOPVisitor import JSONObjectNOPVisitor


def relational_header(xname1: str, xname2: str, header: str) -> str:
    lines: List[str] = []
    lines.append("=" * 80)
    lines.append(
        "||"
        + ("CodeHawk Relational Analysis: " + header).ljust(76)
        + "||")
    lines.append("||" + "  - " + str(xname1).ljust(72) + "||")
    lines.append("||" + "  - " + str(xname2).ljust(72) + "||")
    lines.append("=" * 80)
    return "\n".join(lines)


def relational_footer() -> str:
    lines: List[str] = []
    lines.append("=" * 80)
    lines.append("||" + (str(datetime.datetime.now()) + "  ").rjust(76) + "||")
    lines.append("=" * 80)
    return "\n".join(lines)


def summary_header(maxnamelen: int) -> str:
    lines: List[str] = []
    lines.append(
        "function".ljust(maxnamelen)
        + "moved to".ljust(12)
        + "md5-equal".ljust(12)
        + "cfg-isomorphic".ljust(18)
        + "blocks-changed".ljust(12))
    lines.append("-" * 80)
    return "\n".join(lines)


def details_header() -> str:
    lines: List[str] = []
    lines.append("")
    lines.append("=" * 80)
    lines.append("Functions changed")
    lines.append("=" * 80)
    return "\n".join(lines)


def function_comparison_header() -> str:
    lines: List[str] = []
    lines.append(
        "block".ljust(12)
        + "moved".ljust(15)
        + "md5-equivalent".ljust(15)
        + "instrs-changed".ljust(15)
        + "instrs-added".ljust(14)
        + "instrs-removed".ljust(14))
    lines.append("-" * 80)
    return "\n".join(lines)


class JSONRelationalReport(JSONObjectNOPVisitor):

    def __init__(self) -> None:
        self._report: List[str] = []
        self._show_block_changes: bool = False
        self._show_instr_changes: bool = False
        self._trampoline_blocks: List[FunC.JSONCfgBlockMappingItem] = []

    @property
    def show_block_changes(self) -> bool:
        return self._show_block_changes

    @property
    def show_instr_changes(self) -> bool:
        return self._show_instr_changes

    def add_txt(self, s: str) -> None:
        self._report.append(s)

    def summary_report(
            self,
            obj: AppC.JSONAppComparison,
            block_changes: bool = False,
            instr_changes: bool = False) -> str:
        # Showing instruction changes requires showing basic block level changes
        if instr_changes:
            self._show_block_changes = True
            self._show_instr_changes = True
        else:
            self._show_block_changes = block_changes
            self._show_instr_changes = False

        self.add_txt(relational_header(
            obj.file1, obj.file2, "functions comparison"))
        obj.accept(self)
        self.add_txt(relational_footer())
        return "\n".join(self._report)

    def visit_app_comparison(self, obj: AppC.JSONAppComparison) -> None:
        if not obj.functions_changed:
            return

        maxnamelen = max(len(n.display_name) for n in obj.functions_changed) + 3
        self.add_txt(summary_header(maxnamelen))

        totalblocks = 0

        # XXX: Should this loop over obj.functions_compared instead so we can
        # report on functions not found? see line 292 in relational/RelationalAnalysis.py
        for fn_changed in obj.functions_changed:
            fn_name = fn_changed.display_name

            if fn_changed.faddr1 != fn_changed.faddr2:
                moved = "moved"
            else:
                moved = "not moved"

            if "md5" in fn_changed.changes:
                md5eq = "no"
            else:
                md5eq = "yes"

            if "cfg-structure" in fn_changed.changes:
                streq = "no"
            else:
                streq = "yes"

            blockschanged = fn_changed.num_blocks_changed
            allblocks = fn_changed.num_blocks1
            blchg = str(blockschanged) + "/" + str(allblocks)

            totalblocks += blockschanged

            self.add_txt(
                fn_name.ljust(maxnamelen)
                + moved.ljust(16)
                + md5eq.ljust(12)
                + streq.ljust(18)
                + blchg.ljust(12))

        self.add_txt("\n\nSummary")
        self.add_txt("-" * 80)
        self.add_txt("  Total number of blocks changed: " + str(totalblocks))

        if self.show_block_changes:
            self.add_txt(details_header())
            for fn_changed in obj.functions_changed:
                fn_changed.accept(self)

    def visit_function_comparison(
            self, obj: FunC.JSONFunctionComparison) -> None:
        if obj.name1:
            name = obj.name1
        else:
            name = obj.faddr1

        self.add_txt("\nFunction " + name)
        self.add_txt(function_comparison_header())

        # Because of the visitor pattern, we are doing a depth first walk of
        # the changes, but we want to print them as breath-first. So we
        # collect the text to report at the deepest level (instruction changes) in
        # this list and then print it once we're done with the shallow level
        # (block changes).
        self.instr_changes_txt: List[str] = []

        for block_mapping in obj.cfg_block_mapping:
            block_mapping.accept(self)

        for block_mapping in self._trampoline_blocks:
            self._print_trampoline_info(block_mapping)

        self._report.extend(self.instr_changes_txt)

    def _print_trampoline_info(self, block: FunC.JSONCfgBlockMappingItem) -> None:
        # TODO: In FunctionRelationalAnalysis:report we print save and restore context
        # and register saves and restores (see setup_restore_context_comparison)
        setupblock = block.trampoline_address()
        if setupblock is None:
            raise Exception("Couldn't find trampoline address. Blocks and roles are %s" %
                            block.cfg2_blocks)

        self.add_txt("\nTrampoline for block %s inserted at %s with the "
                     "following components:" % (block.cfg1_block_addr, setupblock))
        for (addr, role) in block.cfg2_blocks:
            if role in ("entry", "exit"):
                continue
            self.add_txt("  " + role.ljust(30) + ": " + addr)


    def visit_cfg_block_mapping_item(self,
                                     obj: FunC.JSONCfgBlockMappingItem,
                                    ) -> None:
        def add_txt(obj: FunC.JSONCfgBlockMappingItem,
                    moved: str, md5eq: str,
                    instrs_changed: str = "-",
                    instrs_added: str = "-",
                    instrs_removed: str = "-",
                   ) -> None:
            self.add_txt(obj.cfg1_block_addr.ljust(12) + moved.ljust(15) +
                         md5eq.ljust(15) + instrs_changed.ljust(15) +
                         instrs_added.ljust(14) + instrs_removed.ljust(14))

        # easy case
        if not obj.changes:
            add_txt(obj, "no", "yes")
            return

        if obj.has_trampoline():
            self._trampoline_blocks.append(obj)
            first_col = "split into trampoline"
            add_txt(obj, first_col, "", "", "", "")
        else:
            # paranoia
            if len(obj.cfg2_blocks) != 1:
                raise RuntimeError("Unexpectedly got more than one patched block when "
                                   "expecting a single-mapped mapping: %s" % obj)

            cfg2_block = obj.cfg2_blocks[0]
            if cfg2_block[0] == obj.cfg1_block_addr:
                moved = "no"
            else:
                moved = "yes"
            md5eq = "yes" if "md5" in obj.matches else "no"

            if md5eq == "no":
                block_comparison = obj.block_comparison
                if not block_comparison:
                    raise RuntimeError("Unexpectedly got a changed function without "
                                       "block comparison details. This should not happen. "
                                       "Change function: %s" % obj)

                num_instrs_changed = len(block_comparison.summary_instructions_changed)
                instr_count = obj.instr_count1
                instrs_changed = f"{num_instrs_changed} / {instr_count}"
                instrs_added = str(len(block_comparison.summary_instructions_added))
                instrs_removed = str(len(block_comparison.summary_instructions_removed))
                add_txt(obj, moved, md5eq, instrs_changed, instrs_added, instrs_removed)
            else:
                add_txt(obj, moved, md5eq)

        if self.show_instr_changes:
            if obj.block_comparison:
                self.instr_changes_txt.append("\nInstruction-level changes in block %s:" %
                                              obj.cfg1_block_addr)
                obj.block_comparison.accept(self)

    def visit_block_comparison(self, obj: BlockC.JSONBlockComparison) -> None:
        if obj.instructions_changed:
            self.instr_changes_txt.append("\n- Instructions changed:")
            for instr_comp in obj.instructions_changed:
                self.instr_changes_txt.append("")
                instr_comp.accept(self)

        if obj.instructions_removed:
            # XXX: Untested
            self.instr_changes_txt.append("\n- Instructions removed:")
            for instr_comp in obj.instructions_removed:
                self.instr_changes_txt.append("")
                instr_comp.accept(self)

        if obj.instructions_added:
            self.instr_changes_txt.append("\n- Instructions added:")
            for new_instr in obj.instructions_added:
                self.instr_changes_txt.append("")
                new_instr.accept(self)

    def visit_instruction_comparison(
            self, obj: InstrC.JSONInstructionComparison) -> None:
        instr2  = obj.instr2
        if instr2 is not None:
            if obj.iaddr1 == obj.iaddr2:
                moved = ""
            else:
                moved = " (moved)"
            self.instr_prefix = "V"
            self.instr_suffix = ""
            obj.instr1.accept(self)
            self.instr_prefix = "P"
            self.instr_suffix = moved
            instr2.accept(self)
        else:
            self.instr_prefix = "V"
            self.instr_suffix = ""
            obj.instr1.accept(self)
            self.instr_changes_txt.append("  P: not mapped")

    def visit_assembly_instruction(self, obj: JSONAssemblyInstruction) -> None:
        self.instr_changes_txt.append(
            "  " + self.instr_prefix + ": "
            + obj.addr[0].ljust(8)
            + "  "
            + obj.bytes.ljust(8)
            + "  "
            + obj.opcode[0].ljust(8)
            + "  "
            + obj.opcode[1].ljust(16)
            + " "
            + obj.annotation
            + self.instr_suffix)
