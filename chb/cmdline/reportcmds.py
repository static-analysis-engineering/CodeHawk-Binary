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

from typing import Dict, List, NoReturn, Tuple

import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI

import chb.util.fileutil as UF


def report_calls(args: argparse.Namespace) -> NoReturn:

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
    
    calls = app.call_instructions()
    calllist: List[Tuple[str, str]] = []

    for faddr in sorted(calls):
        print("\nFunction " + faddr)
        for baddr in calls[faddr]:
            print("  Block " + baddr)
            for instr in calls[faddr][baddr]:
                calllist.append((instr.annotation, faddr))
                print("     " + str(instr))

    print("\nCalls aggregated")
    print("------------------")
    for (c, faddr) in sorted(calllist):
        print(faddr.ljust(12) + c)


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
        print(faddr + ": " + str(fknown).rjust(4) + " / " + str(ftotal).ljust(4))

    perc = (loadknown / loadtotal) * 100
    fperc = "{:.2f}".format(perc)
    print("\nTotal: " + str(loadknown) + " / " + str(loadtotal) + " (" + fperc + "%)")

    print("\nStore statistics")
    print("------------------")
    storetotal = 0
    storeknown = 0
    for faddr in sorted(storestats):
        ftotal = storestats[faddr][0]
        fknown = storestats[faddr][1]
        storetotal += ftotal
        storeknown += fknown
        print(faddr + ": " + str(fknown).rjust(4) + " / " + str(ftotal).ljust(4))

    perc = (storeknown / storetotal) * 100
    fperc = "{:.2f}".format(perc)
    print("\nTotal: " + str(storeknown) + " / " + str(storetotal) + " (" + fperc + "%)")
    exit(0)
