# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024-2025  Aarno Labs, LLC
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
"""Collects the ongoing validation of a patch.

The PatchParticulars class forms the main access point for the patch results
file as produced by the patcher. It also serves as a central collector for
the results of checks performed on the binary to verify compliance with
predefined requirements on structure and semantics of the different kinds of
patch events.

A patch results file may contain multiple patches, called patch events.

Currently three kinds of patch events are supported, identified as such by the
"patchkind" property of a patch event:
- Replacement
- Trampoline
- TrampolineMinimalPair2and3

The structure and properties of each of these three kinds of patch events
are detailed below.

Some nomenclature for trampolines:

- trampoline hook: an unconditional jump instruction within the patched
  function to the trampoline wrapper;
- trampoline body: the code implementing the patch functionality, typically
  a compiled C function based on the user's inserted C code
- trampoline wrapper: code supporting the trampoline body, which may include
  saving and restoring context, diverting control flow, replicating the
  instructions overwritten by the hook, etc.
- trampoline unhook: an unconditional jump instruction from the trampoline
  wrapper back to the original function
- trampoline payload: designation of the functional part of the patch, which
  may either reside in the trampoline body or in the trampoline wrapper.

Patch event structures
======================

Trampoline
^^^^^^^^^^

The regular trampoline patch consists of a wrapper and a payload, where
the payload is implemented as a separate function with arbitrary control
flow. The return value of the payload function determines the control flow
after the payload function returns.

Paraphrased from the patcher documentation:

The payload function takes one argument, a pointer to the saved registers,
and returns an integer return code. A return value of zero indicates the
fallthrough path. Non-zero return values can either be the addresses of
targeted instructions or small integer values used for different syntactic
control flow instructions with statically known destinations.

The wrapper consists of a prelude and an epilog. The prelude typically saves
all registers to the stack and calls the payload function, passing a pointer
to the saved registers. The epilog typically restores the saved registers
and then executes the control flow as determined by the return value of the
payload function:

- 0: fallthrough
- 1: function return
- 2: continue

Each of these cases may or may not replicate the instructions overwritten
by the hook.


Patch validation
================

The approach currently adopted towards patch validation is to accept only
a narrowly specified set of patch events and performing a predefined set
of conservative consistency and compliance checks of the presented assembly
code in relation to the patch event data based on patches encountered so far.
"""
from dataclasses import dataclass
from typing import Any, cast, Dict, List, Optional, TYPE_CHECKING

from chb.jsoninterface.JSONResult import JSONResult

from chb.relational.TraceSimulation import LockStepSimulationStep

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.app.Function import Function
    from chb.app.Instruction import Instruction
    from chb.cmdline.PatchResults import PatchResults, PatchEvent, PatchWrapper
    from chb.invariants.InvariantFact import InvariantFact


class PatchComponent:

    def __init__(self) -> None:
        pass

    @property
    def is_hook(self) -> bool:
        return False

    @property
    def is_code_fragment(self) -> bool:
        return False

    @property
    def kind(self) -> str:
        return "?"

    def to_json_result(self) -> JSONResult:
        return JSONResult("patchcomponent", {}, "fail", "component n/a")

    def __str__(self) -> str:
        return "patch component"


class HookInstruction(PatchComponent):
    """Unconditional jump instruction from or to trampoline.

    Assumptions:

    - instr is a direct unconditional jump instruction
    """

    def __init__(self, instr: "Instruction") -> None:
        self._instr = instr

    @property
    def is_hook(self) -> bool:
        return True

    @property
    def kind(self) -> str:
        return "hook"

    @property
    def instr(self) -> "Instruction":
        return self._instr

    @property
    def srca(self) -> str:
        return self.instr.iaddr

    @property
    def i_srca(self) -> int:
        return int(self.srca, 16)

    @property
    def tgta(self) -> str:
        return str(self.instr.jump_target)

    @property
    def i_tgta(self) -> int:
        return int(self.tgta, 16)

    @property
    def size(self) -> int:
        return self.instr.size

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["srca"] = self.srca
        content["tgta"] = self.tgta
        content["size"] = self.size
        r = self.instr.to_json_result()
        if r.is_ok:
            content["instr"] = r.content
        else:
            return JSONResult("hookinstr", {}, "fail", r.reason)
        return JSONResult("hookinstr", content, "ok")

    def __str__(self) -> str:
        return f"Hook: {self.instr}"


class CodeFragment(PatchComponent):
    """Contiguous instructions within a basic block.

    Assumptions:

    - All instructions are contiguous
    - No control-flow instructions (calls are ok)
    - Code fragment may be empty
    - If code fragment is nonempty starta coincides with iaddr of first
      instruction of the code fragment
    """

    def __init__(self, starta: str, fragment: List["Instruction"]) -> None:
        self._starta = starta
        self._fragment = fragment

    @property
    def is_code_fragment(self) -> bool:
        return True

    @property
    def kind(self) -> str:
        return "codefragment"

    @property
    def is_empty(self) -> bool:
        return len(self.code_fragment) == 0

    @property
    def starta(self) -> str:
        return self._starta

    @property
    def i_starta(self) -> int:
        return int(self.starta, 16)

    @property
    def code_fragment(self) -> List["Instruction"]:
        return self._fragment

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["starta"] = self.starta
        content["instructions"] = instrs = []
        for instr in self.code_fragment:
            r = instr.to_json_result()
            if r.is_ok:
                instrs.append(r.content)
            else:
                return JSONResult("codefragment", {}, "fail", r.reason)
        return JSONResult("codefragment", content, "ok")

    def __str__(self) -> str:
        if self.is_empty:
            return f"Empty (startaddr: {self.starta})"
        else:
            return "\n".join(str(i) for i in self.code_fragment)


class PatchComponentResult:

    def __init__(
            self,
            patchcomponent: Optional[PatchComponent] = None,
            msgs: Optional[List[str]] = None
    ) -> None:
        self._patchcomponent = patchcomponent
        self._msgs = msgs

    @property
    def is_ok(self) -> bool:
        return self._patchcomponent is not None

    @property
    def is_error(self) -> bool:
        return self._msgs is not None

    def get_ok(self) -> PatchComponent:
        if self._patchcomponent is not None:
            return self._patchcomponent
        else:
            raise UF.CHBError(
                "Patch component is not ok: " + ", ".join(self.get_error()))

    def get_error(self) -> List[str]:
        if self._msgs is not None:
            return self._msgs
        else:
            raise UF.CHBError(f"Patch component is not in error.")

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        if self.is_ok:
            content["kind"] = self.get_ok().kind
            r = self.get_ok().to_json_result()
            if r.is_ok:
                content["value"] = r.content
            else:
                return JSONResult("patchcomponent", {}, "fail", r.reason)
        else:
            msg = "; ".join(self.get_error())
            return JSONResult("patchcomponent", {}, "fail", msg)
        return JSONResult("patchcomponent", content, "ok")

    def __str__(self) -> str:
        if self.is_ok:
            return str(self.get_ok())
        else:
            return ", ".join(self.get_error())


class PatchComponentSuccess(PatchComponentResult):

    def __init__(self, patchcomponent: PatchComponent) -> None:
        PatchComponentResult.__init__(self, patchcomponent=patchcomponent)


class PatchComponentFailure(PatchComponentResult):

    def __init__(self, msgs: List[str]) -> None:
        PatchComponentResult.__init__(self, msgs=msgs)


class PatchEventParticulars:

    def __init__(
            self,
            patchevent: "PatchEvent",
            xfun1: "Function",
            xfun2: "Function") -> None:
        self._patchevent = patchevent
        self._xfun1 = xfun1
        self._xfun2 = xfun2
        self._patchcomponents: Optional[Dict[str, PatchComponentResult]] = None

    @property
    def faddr(self) -> str:
        return self.function1.faddr

    @property
    def event(self) -> "PatchEvent":
        return self._patchevent

    @property
    def patchkind(self) -> str:
        return self.event.patchkind

    @property
    def function1(self) -> "Function":
        return self._xfun1

    @property
    def function2(self) -> "Function":
        return self._xfun2

    @property
    def patchcomponents(self) -> Dict[str, PatchComponentResult]:
        return {}

    @property
    def is_trampoline(self) -> bool:
        return False

    def to_json_result(self) -> JSONResult:
        return JSONResult("patchcomponents", {}, "fail", "no validation available")

    def __str__(self) -> str:
        return self.patchkind


class PatchParticulars:

    def __init__(
            self,
            patchresults: "PatchResults",
            app1: "AppAccess",
            app2: "AppAccess") -> None:
        self._patchresults = patchresults
        self._app1 = app1
        self._app2 = app2
        self._events: Optional[Dict[str, "PatchEvent"]] = None

    @property
    def patchresults(self) -> "PatchResults":
        return self._patchresults

    @property
    def app1(self) -> "AppAccess":
        return self._app1

    @property
    def app2(self) -> "AppAccess":
        return self._app2

    @property
    def events(self) -> Dict[str, "PatchEvent"]:
        if self._events is None:
            self._events = {}
            for event in self.patchresults.events:
                self._events[event.logicalva] = event
        return self._events

    def has_patch_event(self, fn: "Function") -> bool:
        for va in self.events:
            if fn.within_function_extent(va):
                return True
        else:
            return False

    def patchevent_particulars(
            self,
            fn1: "Function",
            fn2: "Function") -> Optional[PatchEventParticulars]:
        for va in self.events:
            if fn1.within_function_extent(va):
                event = self.events[va]
                kind = event.patchkind
                chklogger.logger.critical(
                    "patch kind %s not yet supported for comparison",
                    kind)
                return None
        else:
            raise UF.CHBError("No patch event found for function {fn.faddr]")
