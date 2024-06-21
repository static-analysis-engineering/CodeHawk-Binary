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

TrampolinePairMinimal2and3
^^^^^^^^^^^^^^^^^^^^^^^^^^

The simplest trampoline patch consists of just a wrapper, a single basic
block that both implements the desired functionality and replicates the
instructions overwritten by the trampoline hook, and an unconditional jump
back to the next instruction in the original function.

Strictly speaking this patch consists of two patches combined into a single
trampoline, with potentially code before the first (asm) insertion, code between
the two insertions, and code after the second (asm) insertion.

An example of such a patch
is the insertion of interrupt-enable/interrupt-disable instructions to
provide synchronization for memory operations that otherwise may give rise
to race conditions.

The only relevant component of this kind of patch event is the wrapper, with
the following properties:

- logicalva: the hex address of the hook in the original function
- details.wrapper.vahex: the hex address of the first instruction of the wrapper
  (the target address of the hook)
- extras.labeloffsets.case_fallthrough_jump: the (integer) offset of the
  trampoline unhook relative to the start of the wrapper
- destinations.fallthrough: the (integer) address of the target of the
  trampline unhook
- cases: the control-flow options following the payload

The structure of the payload itself is described by the following properties
(all in extras.labeloffsets, represented by integer offsets from the start
of the wrapper):

- execute_before_payload
- asm1
- execute_mid_payload
- asm2
- execute_after_payload


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

TrampolinePairMinimal2and3
^^^^^^^^^^^^^^^^^^^^^^^^^^

Patch events currently accepted:

- logicalva: any address in the patched function F
- details.wrapper.vahex: any address in the code
- extras.labeloffsets.case_fallthrough_jump: any positive integer (aligned)
- destinations.fallthrough: an integer that translates to an address in the
  patched function
- details.cases = ["fallthrough"]

extras.labeloffsets:

- execute_before_payload: 0
- asm1: non-negative integer
- execute_mid_payload: non-negative integer
- asm2: non-negative integer
- execute_after_payload: non-negative integer

Checks performed:

- logicalva is in F and is the address of an unconditional jump instruction
  (to address W)
- details.wrapper.vahex is equal to W
- extras.labeloffsets.case_fallthrough_jump + W reachable from W and is the
  address of an unconditional jump instruction (to address H')
- address H' is reachable from logicalva in the unpatched function

- asm1 >= 0
- execute_mid_payload > asm1
- asm2 > execute_mid_payload
- execute_after_payload > asm2
- case_fallthrough_jump >= execute_after_payload

Data gathered:

- instruction(s) overwritten by the hook
- instruction(s) bypassed by the trampoline (instructions on the path
  between hook and H')
- execute_before instructions
- asm1 instructions
- execute_mid instructions
- execute_after instructions

Validation:

- instructions bypassed by the trampoline = {}
- execute_before instructions = {}
- execute_mid instructions = instructions overwritten by the hook
  (syntactically and semantically)
- execute_after instructions = {}
- asm1 is a semantic NOP
- asm2 is a semantic NOP

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


class Min2And3PatchEventParticulars(PatchEventParticulars):

    def __init__(
            self,
            patchevent: "PatchEvent",
            xfun1: "Function",
            xfun2: "Function") -> None:
        PatchEventParticulars.__init__(self, patchevent, xfun1, xfun2)

    @property
    def is_trampoline(self) -> bool:
        return True

    @property
    def hook(self) -> PatchComponentResult:
        logicalva = self.event.logicalva
        f2instr = self.function2.instructions[logicalva]
        if f2instr.is_jump_instruction:
            if f2instr.jump_target is None:
                return PatchComponentFailure(["Jump instruction has no target"])
            else:
                if f2instr.jump_target.is_int_constant:
                    return PatchComponentSuccess(HookInstruction(f2instr))
                else:
                    return PatchComponentFailure(
                        ["Jump instruction does not have a constant target"])
        else:
            return PatchComponentFailure(["Hook is not a jump instruction"])

    @property
    def unhook(self) -> PatchComponentResult:
        jumpaddr = self.event.case_fallthrough_jump
        if jumpaddr is not None:
            jinstr = self.function2.instructions[jumpaddr]
            if jinstr.is_jump_instruction:
                if jinstr.jump_target is None:
                    return PatchComponentFailure(
                        ["Jump instruction has no target"])
                else:
                    if jinstr.jump_target.is_int_constant:
                        return PatchComponentSuccess(HookInstruction(jinstr))
                    else:
                        return PatchComponentFailure(
                            ["Unhook is an indirect jump"])
            else:
                return PatchComponentFailure(["Unhook is not a jump instruction"])
        else:
            return PatchComponentFailure(
                ["Unhook address not found in patch event"])

    @property
    def execute_before_payload(self) -> str:
        return self.event.label_address("execute_before_payload")

    @property
    def body(self) -> str:
        return self.event.label_address("body")

    @property
    def asm1(self) -> str:
        return self.event.label_address("asm1")

    @property
    def asm2(self) -> str:
        return self.event.label_address("asm2")

    @property
    def execute_mid_payload(self) -> str:
        return self.event.label_address("execute_mid_payload")

    @property
    def execute_after_payload(self) -> str:
        return self.event.label_address("execute_after_payload")

    @property
    def wrapper(self) -> "PatchWrapper":
        return self.event.wrapper

    def mk_code_fragment(self, s: int, e: int) -> PatchComponentResult:
        n = e - s
        instrs: List["Instruction"] = []
        offset: int = 0
        while offset < n:
            iaddr = hex(s + offset)
            instr = self.function2.instructions[iaddr]
            instrs.append(instr)
            offset += instr.size
        return PatchComponentSuccess(CodeFragment(hex(s), instrs))

    @property
    def pre_asm_code_fragment(self) -> PatchComponentResult:
        return self.mk_code_fragment(
            int(self.execute_before_payload, 16), int(self.asm1, 16))

    @property
    def post_asm_code_fragment(self) -> PatchComponentResult:
        fallthrough = self.event.case_fallthrough_jump
        if fallthrough is not None:
            return self.mk_code_fragment(
                int(self.execute_after_payload, 16), int(fallthrough, 16))
        else:
            return PatchComponentFailure(["Fallthrough jump address is missing"])

    @property
    def asm1_code_fragment(self) -> PatchComponentResult:
        return self.mk_code_fragment(
            int(self.asm1, 16), int(self.execute_mid_payload, 16))

    @property
    def asm2_code_fragment(self) -> PatchComponentResult:
        return self.mk_code_fragment(
            int(self.asm2, 16), int(self.execute_after_payload, 16))

    @property
    def instrs_overwritten(self) -> PatchComponentResult:
        if self.hook.is_ok:
            hookinstr = cast(HookInstruction, self.hook.get_ok())
            n_overwritten = hookinstr.size
            hiaddr = hookinstr.srca
            i_hiaddr = hookinstr.i_srca
            instrs: List["Instruction"] = []
            offset: int = 0
            while offset < n_overwritten:
                iaddr = hex(i_hiaddr + offset)
                instr = self.function1.instructions[iaddr]
                instrs.append(instr)
                offset += instr.size
            return PatchComponentSuccess(CodeFragment(hiaddr, instrs))
        else:
            msgs = self.hook.get_error() + ["No hook available"]
            return PatchComponentFailure(msgs)

    @property
    def instrs_midpayload(self) -> PatchComponentResult:
        n_midpayload = int(self.asm2, 16) - int(self.execute_mid_payload, 16)
        instrs: List["Instruction"] = []
        offset: int = 0
        while offset < n_midpayload:
            iaddr = hex(int(self.execute_mid_payload, 16) + offset)
            instr = self.function2.instructions[iaddr]
            instrs.append(instr)
            offset += instr.size
        return PatchComponentSuccess(CodeFragment(
            self.execute_mid_payload, instrs))

    @property
    def patchcomponents(self) -> Dict[str, PatchComponentResult]:
        if self._patchcomponents is None:
            self._patchcomponents = {}
            d = self._patchcomponents
            d["hook"] = self.hook
            d["unhook"] = self.unhook
            d["pre_asm_code_fragment"] = self.pre_asm_code_fragment
            d["post_asm_code_fragment"] = self.post_asm_code_fragment
            d["asm1_code_fragment"] = self.asm1_code_fragment
            d["asm2_code_fragment"] = self.asm2_code_fragment
            d["instrs_overwritten"] = self.instrs_overwritten
            d["instrs_midpayload"] = self.instrs_midpayload
        return self._patchcomponents

    def lockstep_simulation(self) -> JSONResult:
        """Specify lock step simulation relationships.

        Checks performed:
        - invariants at entry states of instructions overwritten match
        - instructions overwritten are duplicated exactly (semantically)
        """

        content: Dict[str, Any] = {}
        content["simsteps"] = []
        cr_overwritten = self.patchcomponents["instrs_overwritten"]
        cr_midpayload = self.patchcomponents["instrs_midpayload"]
        if cr_overwritten.is_error:
            msgs = "; ".join(cr_overwritten.get_error())
            return JSONResult("patchlockstep", {}, "fail", msgs)
        c_overwritten = cast("CodeFragment", cr_overwritten.get_ok())
        if cr_midpayload.is_error:
            msgs = "; ".join(cr_midpayload.get_error())
            return JSONResult("patchlockstep", {}, "fail", msgs)
        c_midpayload = cast("CodeFragment", cr_midpayload.get_ok())
        if len(c_overwritten.code_fragment) != len(c_midpayload.code_fragment):
            len1 = len(c_overwritten.code_fragment)
            len2 = len(c_midpayload.code_fragment)
            reason = (
                "length of overwritten code and midpayload differ: "
                + str(len1)
                + " vs "
                + str(len2))
            return JSONResult("patchlockstep", {}, "fail", reason)
        for (i1, i2) in zip(
                c_overwritten.code_fragment, c_midpayload.code_fragment):
            sim = LockStepSimulationStep(
                self.function1,
                self.function2,
                i1.iaddr,
                i2.iaddr)
            sim.compare_invariants()
            sim.compare_transitions()
            simresult = sim.to_json_result()
            if simresult.is_ok:
                content["simsteps"].append(simresult.content)
            else:
                return JSONResult("patchlockstep", {}, "fail", simresult.reason)
        return JSONResult("patchlockstep", {}, "ok")


    def to_json_result(self) -> JSONResult:
        """Validate existence and internal consistency of all patch components."""
        content: Dict[str, Any] = {}
        content["patchkind"] = "TrampolinePairMin2And3"
        content["components"] = []
        for (role, pc) in self.patchcomponents.items():
            componentrole: Dict[str, Any] = {}
            r = pc.to_json_result()
            if r.is_ok:
                componentrole["role"] = role
                componentrole["component"] = r.content
                content["components"].append(componentrole)
            else:
                return JSONResult("patchvalidation", {}, "fail", r.reason)
        simulationresult = self.lockstep_simulation()
        if simulationresult.is_ok:
            content["simulation"] = simulationresult.content
        else:
            return JSONResult(
                "patchvalidation", {}, "fail", simulationresult.reason)
        return JSONResult("patchvalidation", content, "ok")

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("min2and3 for " + self.faddr)
        for pc in self.patchcomponents:
            lines.append(pc)
            lines.append(str(self.patchcomponents[pc]))
            lines.append("")
        return "\n".join(lines)


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
                if kind == "TrampolinePairMinimal2and3":
                    return Min2And3PatchEventParticulars(
                        self.events[va], fn1, fn2)
                else:
                    chklogger.logger.critical(
                        "patch kind %s not yet supported for comparison",
                        kind)
                    return None
        else:
            raise UF.CHBError("No patch event found for function {fn.faddr]")
