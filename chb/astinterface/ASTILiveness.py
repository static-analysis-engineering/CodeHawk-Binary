# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Dan Phung
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024-2025  Aarno Labs LLC
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
"""Address-keyed liveness derived from per-instruction reaching-def facts.

The reaching-definition facts that CodeHawk attaches to each instruction record,
at each USE site, the addresses that DEFINE the value used there (for GP
registers via the reaching-def facts, for NZCV flags via the flag-reaching-def
facts). From those facts this class builds per-address use/kill sets and runs a
standard backward live-variable fixpoint over the function CFG, producing
live-in/live-out sets keyed by instruction address.

This is intentionally sound-by-over-approximation: every use recorded in the
facts is honored (never dropped), while a def that reaches no use may be absent
from the kill set, which can only make a variable appear live longer -- never
shorter. Consumers that use liveness to gate a transformation therefore never
get a false "dead".
"""

from collections import defaultdict

from typing import (
    Callable, Dict, List, Mapping, Optional, Sequence, Set, TYPE_CHECKING,
    Tuple, Union)

from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.app.Function import Function
    from chb.app.Instruction import Instruction
    from chb.invariants.VarInvariantFact import (
        FlagReachingDefFact, ReachingDefFact)


class ASTILiveness:
    """Derives address-keyed liveness for one CodeHawk function."""

    def __init__(self, fn: "Function") -> None:
        self._fn = fn

    @property
    def fn(self) -> "Function":
        return self._fn

    def flag_liveness(self) -> Dict[str, Dict[str, List[str]]]:
        """NZCV flag live-in/live-out per instruction address."""
        (use, kill) = self._use_kill(
            lambda instr: instr.xdata.flag_reachingdefs, warn_on_init=True)
        return self._liveness(use, kill)

    def register_liveness(
            self, registers: Set[str]) -> Dict[str, Dict[str, List[str]]]:
        """GP-register live-in/live-out per instruction address.

        registers is the set of architecture register names (e.g. the keys of
        the register-size map), used to exclude spill slots and stack
        temporaries.
        """
        (use, kill) = self._use_kill(
            lambda instr: instr.xdata.reachingdefs, set(registers))
        return self._liveness(use, kill)

    def _use_kill(
            self,
            get_facts: Callable[
                ["Instruction"],
                Sequence[Optional[Union["FlagReachingDefFact",
                                        "ReachingDefFact"]]]],
            names: Optional[Set[str]] = None,
            warn_on_init: bool = False
    ) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        """Build per-address use and kill (def) sets from reaching-def facts.

        get_facts is called once per instruction and returns that instruction's
        reaching-def facts: instr.xdata.flag_reachingdefs for flags,
        instr.xdata.reachingdefs for registers. Each fact names the variable
        used at that instruction and the addresses that defined the value used
        there, so the fact contributes a use at the instruction and a kill at
        each of those def addresses.

        When names is given, only variables in that set are considered. "PC" is
        always excluded regardless of names. It is not a value a consumer can
        treat as live or dead.

        warn_on_init reports uses whose value is defined on function entry
        rather than by an instruction.
        """

        def is_real_def_site(defloc: str) -> bool:
            """True if defloc is an instruction address that can carry a kill.

            Only "init" is excluded since it is the analysis's marker for a
            value defined on function entry rather than by an instruction, so
            there is no instruction there to do the killing.
            """
            return defloc != "init"

        use: Dict[str, Set[str]] = defaultdict(set)
        kill: Dict[str, Set[str]] = defaultdict(set)
        warned_init: Set[Tuple[str, str]] = set()
        for (iaddr, instr) in self.fn.instructions.items():
            for fact in get_facts(instr):
                if fact is None:
                    continue
                name = str(fact.variable)
                if name == "PC":
                    continue
                if names is not None and name not in names:
                    continue
                use[iaddr].add(name)
                for d in fact.deflocations:
                    da = str(d)
                    if not is_real_def_site(da):
                        if warn_on_init and (iaddr, name) not in warned_init:
                            warned_init.add((iaddr, name))
                            chklogger.logger.info(
                                "flag %s used at %s in function %s is reached by "
                                "an '%s' definition: its value predates function "
                                "entry.",
                                name, iaddr, self.fn.faddr, da)
                        continue
                    kill[da].add(name)
        return (use, kill)

    def _blocks(self) -> Dict[str, List[str]]:
        """Map block address to its instruction addresses in execution order.

        Sorted lexicographically, the same ordering BasicBlock.lastaddr uses.
        Sorting the addresses as numbers instead would raise an exception
        because not every address is plain hex: the analysis writes an inlined
        instruction's address as "F:0x...._0x....".
        """
        result: Dict[str, List[str]] = {}
        for (baddr, block) in self.fn.blocks.items():
            result[baddr] = sorted(block.instructions.keys())
        return result

    def _liveness(
            self,
            use: Dict[str, Set[str]],
            kill: Dict[str, Set[str]]) -> Dict[str, Dict[str, List[str]]]:
        blocks = self._blocks()
        # Read successors through the cfg.edges property, not cfg.successors,
        # which reads the backing map directly and returns nothing until the
        # property has lazily loaded it from XML.
        edges = self.fn.cfg.edges
        (live_in, live_out) = self._backward(blocks, edges, use, kill)
        result: Dict[str, Dict[str, List[str]]] = {}
        for iaddrs in blocks.values():
            for ia in iaddrs:
                lin = sorted(live_in.get(ia, set()))
                lout = sorted(live_out.get(ia, set()))
                if lin or lout:
                    result[ia] = {"live-in": lin, "live-out": lout}
        return result

    def _visit_order(self, blocks: Dict[str, List[str]]) -> List[str]:
        """Block addresses in the order the fixpoint should visit them.

        A backward analysis converges fastest visiting blocks in reverse of
        reverse-postorder, so successors are settled before their predecessors.
        cfg.rpo_sorted_nodes supplies the reverse-postorder. Blocks it omits
        (it is derived from the graph reachable from the entry) are appended, so
        every block is still visited; order only affects how many rounds the
        fixpoint takes, never the result.
        """
        try:
            rpo = list(self.fn.cfg.rpo_sorted_nodes)
        except Exception:
            return list(blocks)
        ordered = [b for b in reversed(rpo) if b in blocks]
        seen = set(ordered)
        return ordered + [b for b in blocks if b not in seen]

    def _backward(
            self,
            blocks: Dict[str, List[str]],
            edges: Mapping[str, Sequence[str]],
            use: Dict[str, Set[str]],
            kill: Dict[str, Set[str]]
    ) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        """Standard iterative backward live-variable analysis.

        Returns (live_in, live_out), each instruction address -> set of live
        names. CodeHawk has no dataflow framework to reuse for the fixpoint
        itself; the CFG traversal it does provide is used via _visit_order.
        """
        block_in: Dict[str, Set[str]] = {b: set() for b in blocks}
        live_in: Dict[str, Set[str]] = {}
        live_out: Dict[str, Set[str]] = {}
        order = self._visit_order(blocks)

        changed = True
        while changed:
            changed = False
            for b in order:
                iaddrs = blocks[b]
                # live-out of the block = union of successors' block-entry sets
                cur_out: Set[str] = set()
                for s in edges.get(b, []):
                    cur_out |= block_in.get(s, set())
                # walk the block backwards, threading live-out -> live-in
                for ia in reversed(iaddrs):
                    live_out[ia] = set(cur_out)
                    lin = use.get(ia, set()) | (cur_out - kill.get(ia, set()))
                    live_in[ia] = lin
                    cur_out = lin
                # cur_out is now the live-in at the block's first instruction
                if cur_out != block_in[b]:
                    block_in[b] = cur_out
                    changed = True

        return (live_in, live_out)
