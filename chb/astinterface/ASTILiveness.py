# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
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

The flag-reaching-definition facts that CodeHawk attaches to each instruction
record, at each USE site, the addresses that DEFINE the flag value used there.
From those facts this class builds per-address use/kill sets and runs a standard
backward live-variable fixpoint over the function CFG, producing live-in/live-out
sets keyed by instruction address.

This is intentionally sound-by-over-approximation: every use recorded in the
facts is honored (never dropped), while a def that reaches no use may be absent
from the kill set, which can only make a flag appear live longer -- never
shorter. Consumers that use liveness to gate a transformation therefore never
get a false "dead".
"""

from collections import defaultdict
from typing import (
    Callable, Dict, List, Optional, Sequence, Set, TYPE_CHECKING, Tuple, Union)

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
            lambda instr: instr.xdata.flag_reachingdefs)
        return self._liveness(use, kill)

    def _use_kill(
            self,
            get_facts: Callable[
                ["Instruction"],
                Sequence[Optional[Union["FlagReachingDefFact",
                                        "ReachingDefFact"]]]],
            names: Optional[Set[str]] = None
            ) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        """Build per-address use and kill (def) sets from reaching-def facts.

        When names is given only variables in that set are considered. Marker
        deflocations/variables that do not denote a real instruction def site
        are skipped, matching ASTIProvenance.resolve_reaching_defs.
        """
        use: Dict[str, Set[str]] = defaultdict(set)
        kill: Dict[str, Set[str]] = defaultdict(set)
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
                    if da == "init" or da.startswith("F"):
                        continue
                    kill[da].add(name)
        return (use, kill)

    def _blocks(self) -> Dict[str, List[str]]:
        """Block address -> its instruction addresses in execution order.

        Sorted lexicographically, matching how BasicBlock orders its own
        instructions. A numeric (int, 16) key would raise on the analysis's
        inlined-instruction addresses (e.g. "F:0x...._0x....").
        """
        result: Dict[str, List[str]] = {}
        for (baddr, block) in self.fn.blocks.items():
            result[baddr] = sorted(block.instructions.keys())
        return result

    def _edges(self) -> Dict[str, List[str]]:
        """Block address -> successor block addresses.

        Read through the cfg.edges property (not cfg.successors, which reads the
        backing map directly and returns nothing until the property has lazily
        loaded it from XML).
        """
        return {b: list(succs) for (b, succs) in self.fn.cfg.edges.items()}

    def _liveness(
            self,
            use: Dict[str, Set[str]],
            kill: Dict[str, Set[str]]) -> Dict[str, Dict[str, List[str]]]:
        blocks = self._blocks()
        edges = self._edges()
        (live_in, live_out) = self._backward(blocks, edges, use, kill)
        result: Dict[str, Dict[str, List[str]]] = {}
        for iaddrs in blocks.values():
            for ia in iaddrs:
                lin = sorted(live_in.get(ia, set()))
                lout = sorted(live_out.get(ia, set()))
                if lin or lout:
                    result[ia] = {"live-in": lin, "live-out": lout}
        return result

    def _backward(
            self,
            blocks: Dict[str, List[str]],
            edges: Dict[str, List[str]],
            use: Dict[str, Set[str]],
            kill: Dict[str, Set[str]]
            ) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        """Standard iterative backward live-variable analysis.

        Returns (live_in, live_out), each instruction address -> set of live
        names.
        """
        block_in: Dict[str, Set[str]] = {b: set() for b in blocks}
        live_in: Dict[str, Set[str]] = {}
        live_out: Dict[str, Set[str]] = {}

        changed = True
        while changed:
            changed = False
            for (b, iaddrs) in blocks.items():
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
