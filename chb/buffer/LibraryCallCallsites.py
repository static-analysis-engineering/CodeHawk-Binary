# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024  Aarno Labs LLC
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

from typing import Any, cast, Dict, List, Optional, TYPE_CHECKING

from chb.invariants.XConstant import XIntConst
from chb.invariants.XNumerical import XNumerical
from chb.invariants.XXpr import XprCompound, XprConstant, XXpr

from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.api.CallTarget import StubTarget
    from chb.api.FunctionStub import SOFunction
    from chb.app.Instruction import Instruction
    from chb.models.BTerm import BTerm, BTermArithmetic
    from chb.models.FunctionSummary import FunctionSummary
    from chb.models.FunctionPrecondition import (
        FunctionPrecondition, PreDerefWrite)


class LibraryCallSideeffect:

    def __init__(
            self,
            summary: "FunctionSummary",
            faddr: str,
            baddr: str,
            instr: "Instruction",
            pre: "PreDerefWrite") -> None:
        self._summary = summary
        self._faddr = faddr
        self._baddr = baddr
        self._instr = instr
        self._pre = pre

    @property
    def summary(self) -> "FunctionSummary":
        return self._summary

    @property
    def faddr(self) -> str:
        return self._faddr

    @property
    def baddr(self) -> str:
        return self._baddr

    @property
    def instr(self) -> "Instruction":
        return self._instr

    @property
    def pre(self) -> "PreDerefWrite":
        return self._pre

    @property
    def destination(self) -> "BTerm":
        return self.pre.destination

    @property
    def length(self) -> "BTerm":
        return self.pre.length

    @property
    def dstarg(self) -> Optional["XXpr"]:
        predest = str(self.destination)
        if predest.startswith("ci:"):
            dstname = predest[3:]
            dstindex = self.summary.parameter_index(dstname)
            if dstindex is not None:
                if len(self.instr.call_arguments) >= dstindex:
                    return self.instr.call_arguments[dstindex - 1]
        return None

    @property
    def dsttype(self) -> str:
        dstarg = self.dstarg
        if dstarg is None:
            return "unknown"
        else:
            if dstarg.is_stack_address:
                return "stack"
            elif dstarg.is_heap_address:
                return "heap"
            elif dstarg.is_global_address:
                return "global"
            elif dstarg.is_global_variable:
                return "global-var"
            elif dstarg.is_function_return_value:
                return "function-returnvalue"
            elif dstarg.is_argument_value:
                return "function-argument"
            else:
                return "unknown"

    @property
    def compound_lenarg(self) -> Optional["XXpr"]:
        """Return an expression composed of multiple arguments.

        Note: this may involve creating new expressions in the xpr-dictionary;
        these new expressions are not saved.
        """
        if not self.length.is_arithmetic_expr:
            raise UF.CHBError(
                f"Not an arithmetic expression: {self.length}")

        xlen = cast("BTermArithmetic", self.length)
        op_b = xlen.operation
        if not str(xlen.arg1).startswith("ci:"):
            chklogger.logger.info(
                "Length arg in %s does not refer to argument: %s",
                self.summary.name, str(self.length))
            return None

        if not str(xlen.arg2).startswith("ci:"):
            chklogger.logger.info(
                "Length arg in %s does not refer to argument: %s",
                self.summary.name, str(self.length))
            return None

        arg1name = str(xlen.arg1)[3:]
        arg2name = str(xlen.arg2)[3:]
        arg1index = self.summary.parameter_index(arg1name)
        arg2index = self.summary.parameter_index(arg2name)

        if arg1index is None:
            chklogger.logger.warning(
                "No parameter found with name %s in summary for %s",
                arg1name, self.summary.name)
            return None

        if arg2index is None:
            chklogger.logger.warning(
                "No parameter found with name %s in summary for %s",
                arg2name, self.summary.name)
            return None

        argcount = len(self.instr.call_arguments)

        if arg1index > argcount:
            chklogger.logger.warning(
                "Parameter index %d is out of range in summary for %s",
                arg1index, self.summary.name)
            return None

        if arg2index > argcount:
            chklogger.logger.warning(
                "Parameter index %d is out of range in summary for %s",
                arg2index, self.summary.name)
            return None

        arg1 = self.instr.call_arguments[arg1index - 1]
        arg2 = self.instr.call_arguments[arg2index - 1]

        if op_b == "times":
            if arg1.is_int_constant:
                if arg1.intvalue == 1:
                    return arg2
            if arg2.is_int_constant:
                if arg2.intvalue == 1:
                    return arg1

            if arg1.is_int_constant and arg2.is_int_constant:
                v1 = arg1.intvalue
                v2 = arg2.intvalue
                numix = XNumerical.mk_instance(arg1.xd, v1 * v2).index
                icstix = XIntConst.mk_instance(arg1.xd, numix).index
                return XprConstant.mk_instance(arg1.xd, icstix)

        op_x = "mult" if op_b == "times" else "plus"
        return XprCompound.mk_instance(arg1.xd, op_x, [arg1.index, arg2.index])

    @property
    def lenarg(self) -> Optional["XXpr"]:
        if self.length.is_arithmetic_expr:
            return self.compound_lenarg

        prelen = str(self.length)
        if prelen.startswith("ci:"):
            lenname = prelen[3:]
            lenindex = self.summary.parameter_index(lenname)
            if lenindex is not None:
                if len(self.instr.call_arguments) >= lenindex:
                    return self.instr.call_arguments[lenindex - 1]
        return None

    @property
    def lentype(self) -> str:
        lenarg = self.lenarg
        if lenarg is not None:
            if lenarg.is_constant:
                return "constant"
            else:
                return "expr"
        else:
            lenterm = str(self.length)
            if lenterm.startswith("cn"):
                return "constant"
            elif lenterm.startswith("null-terminator"):
                return "string-length"
            elif lenterm == "runtime-value":
                return lenterm
            elif lenterm.startswith("plus(null"):
                return "string-concatenation"
            else:
                return lenterm

    def __str__(self) -> str:
        return self.instr.iaddr + ": " + str(self.instr.annotation)


class LibraryCallCallsite:

    def __init__(
            self, faddr: str,
            baddr: str,
            iaddr: str,
            callinstr: "Instruction") -> None:
        self._faddr = faddr
        self._baddr = baddr
        self._iaddr = iaddr
        self._instr = callinstr

    @property
    def faddr(self) -> str:
        return self._faddr

    @property
    def baddr(self) -> str:
        return self._baddr

    @property
    def iaddr(self) -> str:
        return self._iaddr

    @property
    def instr(self) -> "Instruction":
        return self._instr

    @property
    def tgtname(self) -> str:
        return self.stub.name

    @property
    def calltarget(self) -> "StubTarget":
        tgt = self.instr.call_target
        if tgt.is_so_target:
            return cast("StubTarget", tgt)
        raise UF.CHBError(f"Not a stub target: {self.iaddr}")

    @property
    def stub(self) -> "SOFunction":
        tgt = self.calltarget.stub
        if tgt.is_so_stub:
            return cast("SOFunction", tgt)
        raise UF.CHBError(f"Not a shared object library target: {self.iaddr}")

    def has_summary(self) -> bool:
        return self.stub.has_summary()

    @property
    def summary(self) -> "FunctionSummary":
        if self.has_summary():
            return self.stub.summary()
        else:
            raise UF.CHBError(f"Callsite does not have a summary: {self.iaddr}")

    @property
    def preconditions(self) -> List["FunctionPrecondition"]:
        if self.has_summary():
            return self.stub.summary().semantics.preconditions
        else:
            return []

    @property
    def derefwrites(self) -> List[LibraryCallSideeffect]:
        result: List[LibraryCallSideeffect] = []
        for pre in self.preconditions:
            if pre.is_deref_write:
                pre = cast("PreDerefWrite", pre)
                lcwrite = LibraryCallSideeffect(
                    self.summary, self.faddr, self.baddr, self.instr, pre)
                result.append(lcwrite)
        return result

    @property
    def lenarg_exprs(self) -> List["XXpr"]:
        result: List["XXpr"] = []
        for dw in self.derefwrites:
            if dw.lentype == "expr":
                if dw.lenarg is not None:
                    result.append(dw.lenarg)
        return result

    @property
    def known_input_length(self) -> Optional[str]:
        if self.tgtname == "strcpy":
            if self.instr.call_arguments[1].is_string_reference:
                return "strcpy:constant_src"
            else:
                return None
        elif self.tgtname == "sprintf":
            fmtarg = self.instr.call_arguments[1]
            if fmtarg.is_string_reference:
                fmtstr = (cast(XprConstant, fmtarg)).constant.string_reference()
                if not "%s" in fmtstr:
                    return "sprintf:max_length_fmt"
                else:
                    return None
            else:
                return None
        elif self.tgtname == "snprintf":
            fmtarg = self.instr.call_arguments[2]
            if fmtarg.is_string_reference:
                fmtstr = (cast(XprConstant, fmtarg)).constant.string_reference()
                if not "%s" in fmtstr:
                    return "snprintf:max_length_fmt"
                else:
                    return None
            else:
                return None
        else:
            return None

    @property
    def patch_candidates(self) -> List[LibraryCallSideeffect]:
        result: List[LibraryCallSideeffect] = []
        if self.known_input_length is not None:
            return result

        for dw in self.derefwrites:
            if not dw.dsttype == "stack":
                continue

            if dw.lentype == "constant":
                continue

            result.append(dw)

        return result


class LibraryCallCallsites:

    def __init__(self) -> None:
        self._duplicates: Dict[str, Dict[str, List[LibraryCallCallsite]]] = {}
        self._callsites: Dict[str, Dict[str, LibraryCallCallsite]] = {}

    @property
    def callsites(self) -> Dict[str, Dict[str, LibraryCallCallsite]]:
        return self._callsites

    @property
    def duplicates(self) -> Dict[str, Dict[str, List[LibraryCallCallsite]]]:
        return self._duplicates

    def add_library_callsite(
            self, faddr: str, baddr: str, callinstr: "Instruction") -> None:
        iaddr = callinstr.iaddr
        lccs = LibraryCallCallsite(faddr, baddr, iaddr, callinstr)
        self._callsites.setdefault(faddr, {})
        if iaddr in self._callsites[faddr]:
            chklogger.logger.warning(
                "Duplicate instruction in %s: %s", faddr, iaddr)
            self._duplicates.setdefault(faddr, {})
            self._duplicates[faddr].setdefault(iaddr, [])
            self._duplicates[faddr][iaddr].append(lccs)
        else:
            self._callsites[faddr][iaddr] = lccs

    def n_librarycalls(self) -> int:
        return sum(len(ics) for ics in self.callsites.values())

    def n_summarized(self) -> int:
        result: int = 0
        for (_, ics) in self.callsites.items():
            for cs in ics.values():
                if cs.has_summary():
                    result += 1
        return result

    def n_writing_sideeffect(self) -> int:
        result: int = 0
        for (_, ics) in self.callsites.items():
            for cs in ics.values():
                result += len(cs.derefwrites)
        return result

    def sideeffect_destination_types(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for (_, ics) in self.callsites.items():
             for cs in ics.values():
                 for se in cs.derefwrites:
                     dsttype = se.dsttype
                     result.setdefault(dsttype, 0)
                     result[dsttype] += 1
        return result

    def sideeffect_length_types(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for (_, ics) in self.callsites.items():
            for cs in ics.values():
                for se in cs.derefwrites:
                    lentype = se.lentype
                    result.setdefault(lentype, 0)
                    result[lentype] += 1
        return result

    def sideeffect_length_exprs(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for (_, ics) in self.callsites.items():
            for cs in ics.values():
                for x in cs.lenarg_exprs:
                    if x.is_register_variable:
                        s = "unknown"
                    elif x.is_initial_register_value:
                        s = "function argument"
                    else:
                        s = str(x)
                    result.setdefault(s, 0)
                    result[s] += 1
        return result

    def known_input_length_sideeffect_writes(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for (_, ics) in self.callsites.items():
            for cs in ics.values():
                r = cs.known_input_length
                if r is not None:
                    result.setdefault(r, 0)
                    result[r] += 1
        return result

    def patch_candidates(self) -> List["Instruction"]:
        result: List["Instruction"] = []
        for (_, ics) in self.callsites.items():
            for cs in ics.values():
                for c in cs.patch_candidates:
                    result.append(c.instr)
        return result

    def patch_callsites(self) -> List[LibraryCallSideeffect]:
        result: List[LibraryCallSideeffect] = []
        for (_, ics) in self.callsites.items():
            for cs in ics.values():
                result.extend(cs.patch_candidates)
        return result

    def patch_candidates_distribution(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for (_, ics) in self.callsites.items():
            for cs in ics.values():
                for c in cs.patch_candidates:
                    name = c.summary.name
                    result.setdefault(name, 0)
                    result[name] += 1
        return result

    def missing_summaries(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for (_, ics) in self.callsites.items():
            for cs in ics.values():
                if not cs.has_summary():
                    name = cs.stub.name
                    result.setdefault(name, 0)
                    result[name] += 1
        return result

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["library-calls"] = self.n_librarycalls()
        content["summarized"] = self.n_summarized()
        content["sideeffect"] = self.n_writing_sideeffect()
        content["patch-candidates"] = len(self.patch_candidates())
        content["sideeffect-destination-types"] = []
        for (name, count) in self.sideeffect_destination_types().items():
            content["sideeffect-destination-types"].append(
                {"name": name, "count": count})
        content["sideeffect-length-types"] = []
        for (name, count) in self.sideeffect_length_types().items():
            content["sideeffect-length-types"].append(
                {"name": name, "count": count})
        content["known-input-length-types"] = []
        for (name, count) in self.known_input_length_sideeffect_writes().items():
            content["known-input-length-types"].append(
                {"name": name, "count": count})
        content["length-expressions"] = []
        for (name, count) in self.sideeffect_length_exprs().items():
            content["length-expressions"].append(
                {"name": name, "count": count})
        content["patch-candidate-instructions"] = []
        for pc in self.patch_candidates():
            content["patch-candidate-instructions"].append(
                {"address": pc.iaddr, "annotation": pc.annotation[5:]})
        content["patch-candidates-distribution"] = []
        for (name, count) in self.patch_candidates_distribution().items():
            content["patch-candidates-distribution"].append(
                {"name": name, "count": count})
        content["missing-summaries"] = []
        for (name, count) in self.missing_summaries().items():
            content["missing-summaries"].append(
                {"name": name, "count": count})
        return JSONResult("libcboundsstats", content, "ok")
