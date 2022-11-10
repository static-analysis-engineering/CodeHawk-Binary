# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs, LLC
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
"""Initiate relational analysis of two binaries."""

import argparse
import importlib
import json
import os

from typing import cast, Dict, List, NoReturn, Optional, Tuple

import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI

from chb.graphics.DotCfg import DotCfg

from chb.invariants.InvariantFact import NRVFact
from chb.invariants.NonRelationalValue import NonRelationalValue

from chb.relational.RelationalAnalysis import RelationalAnalysis

import chb.util.dotutil as UD
import chb.util.fileutil as UF
import chb.cmdline.commandutil as UC


def relational_analysis_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname1: str = args.xname1
    xname2: str = args.xname2
    xfunctions1: List[str] = args.functions1
    xfunctions2: List[str] = args.functions2
    showfunctions: bool = args.functions
    showinstructions: bool = args.instructions
    cfgsfilename: str = args.cfgs_filename
    invariants: bool = args.invariants
    showcalls: bool = args.calls_in_cfg
    showpredicates: bool = args.predicates_in_cfg
    usermappingfile: Optional[str] = args.usermapping
    callees: List[str] = args.callees

    usermapping: Dict[str, str] = {}
    if usermappingfile is not None:
        if os.path.isfile(usermappingfile):
            with open(usermappingfile, "r") as fp:
                userdata = json.load(fp)
                usermapping = userdata["function-mapping"]
        else:
            UC.print_error(
                "Usermapping file " + usermappingfile + " not found")
            exit(1)

    try:
        (path1, xfile1) = UC.get_path_filename(xname1)
        UF.check_analysis_results(path1, xfile1)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo1 = XI.XInfo()
    xinfo1.load(path1, xfile1)

    try:
        (path2, xfile2) = UC.get_path_filename(xname2)
        UF.check_analysis_results(path2, xfile2)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo2 = XI.XInfo()
    xinfo2.load(path2, xfile2)

    app1 = UC.get_app(path1, xfile1, xinfo1)
    app2 = UC.get_app(path2, xfile2, xinfo2)

    relanalysis = RelationalAnalysis(
        app1,
        app2,
        faddrs1=xfunctions1,
        faddrs2=xfunctions2,
        usermapping=usermapping,
        callees=callees)

    print(relanalysis.report(showfunctions, showinstructions))

    if cfgsfilename is not None:
        functionschanged = relanalysis.functions_changed()
        if len(functionschanged) == 0:
            UC.print_error("No functions changed")
            exit(0)

        dotgraphs: List[DotCfg] = []

        for faddr in functionschanged:
            if faddr in relanalysis.function_mapping:
                fnanalysis = relanalysis.function_analysis(faddr)
                cfgmatcher = fnanalysis.cfgmatcher
                (dotcfg1, dotcfg2) = cfgmatcher.dot_cfgs(
                    showcalls=showcalls, showpredicates=showpredicates)
                dotgraphs.extend([dotcfg1, dotcfg2])
            else:
                dotcfgremoved = DotCfg(
                    "removed",
                    app1.function(faddr),
                    showcalls=showcalls,
                    showpredicates=showpredicates,
                    subgraph=True)
                dotgraphs.append(dotcfgremoved)

        newfunctions = relanalysis.new_functions()
        for faddr in newfunctions:
            dotcfgnew = DotCfg(
                "new",
                app2.function(faddr),
                defaultcolor="orange",
                showcalls=showcalls,
                showpredicates=showpredicates,
                subgraph=True)
            dotgraphs.append(dotcfgnew)

        pdffilename = UD.print_dot_subgraphs(
            app1.path,
            "cfg_comparison",
            cfgsfilename,
            [dotcfg.build() for dotcfg in dotgraphs])

        if os.path.isfile(pdffilename):
            UC.print_info(
                "Control flow graph for "
                + "vulnerable/patched"
                + " has been saved in "
                + pdffilename)
        else:
            UC.print_error(
                "Error in converting dot file to pdf")
            exit(1)

    if invariants:
        functionschanged = relanalysis.functions_changed()
        f1fn = app1.function(functionschanged[0])
        f2fn = app2.function(functionschanged[0])

        f1invariants = f1fn.invariants
        f2invariants = f2fn.invariants

        f1table: Dict[str, Dict[str, NonRelationalValue]] = {}
        f2table: Dict[str, Dict[str, NonRelationalValue]] = {}
        for loc in f1invariants:
            for fact in f1invariants[loc]:
                if fact.is_nonrelational:
                    fact = cast(NRVFact, fact)
                    f1table.setdefault(loc, {})
                    f1table[loc][str(fact.variable)] = fact.value
        for loc in f2invariants:
            for fact in f2invariants[loc]:
                if fact.is_nonrelational:
                    fact = cast(NRVFact, fact)
                    f2table.setdefault(loc, {})
                    f2table[loc][str(fact.variable)] = fact.value
        comparison: Dict[str, Dict[
            str, Tuple[Optional[NonRelationalValue], Optional[NonRelationalValue]]]] = {}
        for loc in f1table:
            comparison.setdefault(loc, {})
            if loc in f2table:
                f1values = f1table[loc]
                f2values = f2table[loc]
                for v1 in f1values:
                    if v1 in f2values:
                        f1value = f1table[loc][v1]
                        f2value = f2table[loc][v1]
                        comparison[loc][v1] = (f1value, f2value)
                    else:
                        f1value = f1table[loc][v1]
                        comparison[loc][v1] = (f1value, None)
            else:
                for v1 in f1values:
                    comparison[loc][v1] = (f1values[v1], None)

        counter: int = 0
        print("\nInvariants modified or missing:")
        print("===================================")
        for loc in sorted(comparison):
            for v in sorted(comparison[loc]):
                values = comparison[loc][v]
                if str(values[0]) == str(values[1]):
                    counter += 1
                else:
                    print(
                        loc.ljust(12)
                        + v.ljust(32)
                        + str(values[0]).ljust(20)
                        + str(values[1]))

        print(
            "\nInvariants not modified: "
            + str(counter)
            + " (in "
            + str(len(f1table))
            + " locations)")
    exit(0)
