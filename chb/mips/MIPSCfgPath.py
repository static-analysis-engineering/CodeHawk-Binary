# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
#
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

from typing import cast, List, Optional, Sequence, Tuple, TYPE_CHECKING

from chb.invariants.InputConstraint import InputConstraint
from chb.invariants.XXpr import XXpr

from chb.mips.MIPSInstruction import MIPSInstruction

if TYPE_CHECKING:
    from chb.mips.MIPSCfg import MIPSCfg


class MIPSCfgPath:

    def __init__(
            self,
            mipscfg: "MIPSCfg",
            path: List[str]) -> None:
        self._mipscfg = mipscfg
        self._path = path

    @property
    def mipscfg(self) -> "MIPSCfg":
        return self._mipscfg

    @property
    def path(self) -> List[str]:
        """Return a list of block addresses."""

        return self._path

    @property
    def is_feasible(self) -> bool:
        return not (any([c is not None and c.is_false for c in self.conditions()]))

    def has_loop_node(self) -> bool:
        return any([self.mipscfg.has_loop_level(b) for b in self.path])

    def conditions(self) -> Sequence[Optional[XXpr]]:
        """Returns conditions per block, condition may be None."""
        result: List[Optional[XXpr]] = []
        for i in range(len(self.path) - 1):
            c = self.mipscfg.condition(self.path[i], self.path[i+1])
            result.append(c)
        return result

    def call_instructions(self) -> List[List[MIPSInstruction]]:
        """Returns calls per block."""
        result: List[List[MIPSInstruction]] = []
        for i in range(len(self.path)):
            calls = cast(
                List[MIPSInstruction],
                self.mipscfg.function.block(self.path[i]).call_instructions)
            result.append(calls)
        return result

    def block_call_instruction_strings(self) -> List[Tuple[str, str, str]]:
        """Returns a list of (blockaddress, callinstr-string)."""

        result: List[Tuple[str, str, str]] = []
        callinstrs = self.call_instructions()
        for i in range(len(self.path)):
            for c in callinstrs[i]:
                result.append((self.path[i], c.iaddr, c.annotation))
        return result

    def constraints(self) -> List[Optional[InputConstraint]]:
        """Returns constraints per block (constraint may be None."""

        result: List[Optional[InputConstraint]] = []
        conditions = self.conditions()
        for c in conditions:
            k = None if c is None else c.to_input_constraint()
            result.append(k)
        return result

    def block_condition_strings(self) -> List[Tuple[str, str]]:
        """Returns a list of (blockaddress, condition-string), with None excluded"""
        result: List[Tuple[str, str]] = []
        conditions = self.conditions()
        for i in range(len(self.path) - 1):
            c = conditions[i]
            if c is None:
                continue
            result.append((self.path[i], str(c)))
        return result

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Blocks: " + ", ".join(b for b in self.path))
        lines.append("Conditions: " + ", ".join(str(c) for c in self.conditions()))
        lines.append("Constraints: " + ", ".join(str(c) for c in self.constraints()))
        return "\n".join(lines)
