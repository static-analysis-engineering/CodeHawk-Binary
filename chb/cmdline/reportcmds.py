#!/usr/bin/env python3
# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs, LLC
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
"""Support functions for the command-line interpreter."""

import argparse
import json

from typing import (
    Any, Callable, cast, Dict, List, NoReturn, Optional, Sequence, Tuple)

from chb.app.Instruction import Instruction

import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI

from chb.invariants.XXpr import XprCompound, XprConstant, XXpr

import chb.util.fileutil as UF


def dst_stack_arg_offset(instr: Instruction, dstargix: int) -> Optional[int]:
    try:
        dstarg = instr.call_arguments[dstargix]
        if dstarg.is_stack_address:
            dstarg = cast(XprCompound, dstarg)
            return (-dstarg.stack_address_offset())
        else:
            print("Not a stack address: " + str(dstarg))
            return None
    except Exception as e:
        print("Exception in " + str(instr) + ": " + str(e))
        return None


destination_arguments: Dict[str, int] = {
    "memcpy": 0,
    "snprintf": 0,
    "sprintf": 0,
    "strlcpy": 0,
    "strcat": 0,
    "strcpy": 0,
    "strlcpy": 0,
    "strncpy": 0
}


class CallRecord:

    def __init__(
            self,
            faddr: str,
            instr: Instruction,
            fname: Optional[str] = None) -> None:
        self._faddr = faddr
        self._fname = fname
        self._instr = instr

    @property
    def instr(self) -> Instruction:
        return self._instr

    @property
    def faddr(self) -> str:
        return self._faddr

    @property
    def iaddr(self) -> str:
        return self.instr.iaddr

    def has_fname(self) -> bool:
        return self._fname is not None

    @property
    def fname(self) -> str:
        if self._fname is not None:
            return self._fname
        else:
            raise UF.CHBError("Function does not have a name")

    @property
    def callee(self) -> str:
        return str(self.instr.call_target)

    @property
    def arguments(self) -> Sequence["XXpr"]:
        return self.instr.call_arguments

    @property
    def write_destination(self) -> Optional[str]:
        if self.callee in destination_arguments:
            argix = destination_arguments[self.callee]
            if len(self.arguments) > argix:
                dstarg = self.arguments[destination_arguments[self.callee]]
            else:
                print("Argument " + str(argix) + " not present for " + self.callee)
                return None
            if dstarg.is_stack_address:
                return "stack"
            elif dstarg.is_heap_address:
                return "heap"
            elif dstarg.is_global_address:
                return "global"
            else:
                return None
        else:
            return None

    def dest_stack_frame_size(self) -> Optional[int]:
        dest = self.write_destination
        if dest and dest == "stack":
            return dst_stack_arg_offset(
                self.instr, destination_arguments[self.callee])
        else:
            return None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        writedst = self.write_destination
        result["faddr"] = self.faddr
        result["iaddr"] = self.iaddr
        if self.has_fname():
            result["fname"] = self.fname
        result["callee"] = self.callee
        result["arguments"] = [str(a) for a in self.arguments]
        if writedst is not None:
            result["writes-to"] = writedst
            if writedst == "stack":
                framesize = self.dest_stack_frame_size()
                if framesize is not None:
                    result["dst-framesize"] = framesize
        return result


def report_calls(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    outputfile: str = args.outputfile
    verbose: bool = args.verbose
    callees: List[str] = args.callees

    try:
        (path, xfile) = UC.get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = UC.get_app(path, xfile, xinfo)

    calls = app.call_instructions()
    calllist: List[CallRecord] = []

    for faddr in sorted(calls):
        fname = (
            app.function_name(faddr)
            if app.has_function_name(faddr)
            else None)
        if verbose:
            print("\nFunction " + faddr)
        for baddr in calls[faddr]:
            for instr in calls[faddr][baddr]:
                calltgt = str(instr.call_target)
                if "all" in callees or calltgt in callees:
                    callrec = CallRecord(faddr, instr, fname=fname)
                    calllist.append(callrec)
                    if verbose:
                        print("     " + str(instr))

    results: Dict[str, Any] = {}
    results["application"] = {}
    results["application"]["name"] = xfile
    results["application"]["md5"] = xinfo.md5
    results["calls"] = [callrec.to_dict() for callrec in calllist]

    filename = outputfile + ".json"
    with open(filename, "w") as fp:
        json.dump(results, fp, indent=2)

    stats: Dict[str, Dict[str, int]] = {}

    for c in calllist:
        callee = c.callee
        stats.setdefault(callee, {})
        dst = c.write_destination
        if dst is None:
            dst = "unknown"
        stats[callee].setdefault(dst, 0)
        stats[callee][dst] += 1

    print("Statistics")
    print("==========")
    for (call, counts) in stats.items():
        print(call + " (" + str(sum([counts[n] for n in counts])) + ")")
        for (d, n) in counts.items():
            print("  " + d.ljust(8) + str(n).rjust(5))

    exit(0)


def report_memops(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname

    try:
        (path, xfile) = UC.get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = UC.get_app(path, xfile, xinfo)

    memloads = app.load_instructions()
    memstores = app.store_instructions()

    loadstats: Dict[str, Tuple[int, int]] = {}
    storestats: Dict[str, Tuple[int, int]] = {}

    def add_load_unknown(faddr: str) -> None:
        loadstats.setdefault(faddr, (0, 0))
        v = loadstats[faddr]
        loadstats[faddr] = (v[0] + 1, v[1])

    def add_load_known(faddr: str) -> None:
        loadstats.setdefault(faddr, (0, 0))
        v = loadstats[faddr]
        loadstats[faddr] = (v[0] + 1, v[1] + 1)

    loadxrefs: Dict[str, List[str]] = {}

    def add_load_xref(gv: str, faddr: str) -> None:
        loadxrefs.setdefault(gv, [])
        loadxrefs[gv].append(faddr)

    print("Load instructions")
    print("-----------------")
    for faddr in sorted(memloads):
        print("\nFunction " + faddr)
        for baddr in memloads[faddr]:
            print("  Block: " + baddr)
            for instr in memloads[faddr][baddr]:
                print("     " + str(instr))
                for rhs in instr.rhs:
                    add_load_xref(str(rhs), faddr)
                    if str(rhs) == "?":
                        add_load_unknown(faddr)
                    else:
                        add_load_known(faddr)

    def add_store_unknown(faddr: str) -> None:
        storestats.setdefault(faddr, (0, 0))
        v = storestats[faddr]
        storestats[faddr] = (v[0] + 1, v[1])

    def add_store_known(faddr: str) -> None:
        storestats.setdefault(faddr, (0, 0))
        v = storestats[faddr]
        storestats[faddr] = (v[0] + 1, v[1] + 1)

    storexrefs: Dict[str, List[str]] = {}

    def add_store_xref(gv: str, faddr: str) -> None:
        storexrefs.setdefault(gv, [])
        storexrefs[gv].append(faddr)

    print("\n\nStore instructions")
    print("----------------------")
    for faddr in sorted(memstores):
        print("\nFunction " + faddr)
        for baddr in memstores[faddr]:
            print("  Block: " + baddr)
            for instr in memstores[faddr][baddr]:
                print("     " + str(instr))
                for lhs in instr.lhs:
                    add_store_xref(str(lhs), faddr)
                    if str(lhs) in ["?", "??operand??"]:
                        add_store_unknown(faddr)
                    else:
                        add_store_known(faddr)

    print("\nLoad xreferences")
    print("------------------")
    for gv in sorted(loadxrefs):
        if gv.startswith("gv_"):
            print(gv.ljust(24) + "[" + ", ".join(loadxrefs[gv]) + "]")

    print("\nStore xreferences")
    print("-------------------")
    for gv in sorted(storexrefs):
        if gv.startswith("gv"):
            print(gv.ljust(24) + "[" + ", ".join(storexrefs[gv]) + "]")

    print("\nLoad statistics")
    print("-----------------")
    loadtotal: int = 0
    loadknown: int = 0
    for faddr in sorted(loadstats):
        ftotal = loadstats[faddr][0]
        fknown = loadstats[faddr][1]
        loadtotal += ftotal
        loadknown += fknown
        print(
            faddr + ": " + str(fknown).rjust(4) + " / " + str(ftotal).ljust(4))

    perc = (loadknown / loadtotal) * 100
    fperc = "{:.2f}".format(perc)
    print(
        "\nTotal: "
        + str(loadknown)
        + " / "
        + str(loadtotal)
        + " ("
        + fperc
        + "%)")

    print("\nStore statistics")
    print("------------------")
    storetotal = 0
    storeknown = 0
    for faddr in sorted(storestats):
        ftotal = storestats[faddr][0]
        fknown = storestats[faddr][1]
        storetotal += ftotal
        storeknown += fknown
        print(
            faddr + ": " + str(fknown).rjust(4) + " / " + str(ftotal).ljust(4))

    perc = (storeknown / storetotal) * 100
    fperc = "{:.2f}".format(perc)
    print(
        "\nTotal: "
        + str(storeknown)
        + " / "
        + str(storetotal)
        + " ("
        + fperc
        + "%)")
    exit(0)
