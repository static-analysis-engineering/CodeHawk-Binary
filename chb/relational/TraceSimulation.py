# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024  Aarno Labs, LLC
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
"""Simulation between two systems."""

from typing import Any, Dict, List, Optional, TYPE_CHECKING

from chb.jsoninterface.JSONResult import JSONResult

if TYPE_CHECKING:
    from chb.app.Function import Function
    from chb.app.Instruction import Instruction
    from chb.invariants.InvariantFact import InvariantFact
    from chb.invariants.XXpr import XXpr


class ExecutionState:
    """Invariant facts at a particular point in an execution."""

    def __init__(self, fn: "Function", iaddr: str) -> None:
         self._fn = fn
         self._iaddr = iaddr
         self._invariants: Optional[List["InvariantFact"]] = None

    @property
    def function(self) -> "Function":
        return self._fn

    @property
    def iaddr(self) -> str:
        return self._iaddr

    @property
    def invariants(self) -> List["InvariantFact"]:
        if self._invariants is None:
            self._invariants = []
            for inv in self.function.invariants[self.iaddr]:
                self._invariants.append(inv)
        return self._invariants

    def to_json_result(self) -> JSONResult:
        schema = "executionstate"
        content: Dict[str, Any] = {}
        content["address"] = self.iaddr
        content["invariants"] = []
        for inv in self.invariants:
            r = inv.to_json_result()
            if r.is_ok:
                content["invariants"].append(r.content)
            else:
                return JSONResult(schema, {}, "fail", r.reason)
        return JSONResult(schema, content, "ok")


class TraceTransition:
    """Transition between two states in an execution."""

    def __init__(self, fn: "Function", iaddr: str) -> None:
        self._fn = fn
        self._iaddr = iaddr

    @property
    def function(self) -> "Function":
        return self._fn

    @property
    def iaddr(self) -> str:
        return self._iaddr

    @property
    def instruction(self) -> Optional["Instruction"]:
        if self.function.has_instruction(self.iaddr):
            return self.function.instruction(self.iaddr)
        else:
            return None


class LockStepSimulationStep:
    """Pair of transitions in original and patched binary."""

    def __init__(
            self,
            fn1: "Function",
            fn2: "Function",
            iaddr1: str,
            iaddr2: str) -> None:
        self._fn1 = fn1
        self._fn2 = fn2
        self._iaddr1 = iaddr1
        self._iaddr2 = iaddr2
        self._transition1: Optional[TraceTransition] = None
        self._transition2: Optional[TraceTransition] = None
        self._src1state: Optional[ExecutionState] = None
        self._src2state: Optional[ExecutionState] = None

    @property
    def function1(self) -> "Function":
        return self._fn1

    @property
    def function2(self) -> "Function":
        return self._fn2

    @property
    def iaddr1(self) -> str:
        return self._iaddr1

    @property
    def iaddr2(self) -> str:
        return self._iaddr2

    @property
    def transition1(self) -> TraceTransition:
        if self._transition1 is None:
            self._transition1 = TraceTransition(self.function1, self.iaddr1)
        return self._transition1

    @property
    def transition2(self) -> TraceTransition:
        if self._transition2 is None:
            self._transition2 = TraceTransition(self.function2, self.iaddr2)
        return self._transition2

    @property
    def src1state(self) -> ExecutionState:
        if self._src1state is None:
            self._src1state = ExecutionState(self.function1, self.iaddr1)
        return self._src1state

    @property
    def src2state(self) -> ExecutionState:
        if self._src2state is None:
            self._src2state = ExecutionState(self.function2, self.iaddr2)
        return self._src2state

    def compare_invariants(self) -> None:
        invs1 = self.src1state.invariants
        invs2 = self.src2state.invariants

    def compare_transitions(self) -> None:
        instr1 = self.transition1.instruction
        instr2 = self.transition2.instruction

    def to_json_result(self) -> JSONResult:
        """Placeholder for now."""

        return JSONResult("simulationstep", {}, "ok")
