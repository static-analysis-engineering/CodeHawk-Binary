# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs, LLC
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
import datetime
import importlib
import json
import os
import subprocess

from typing import Any, cast, Dict, List, NoReturn, Optional, Tuple

from chb.cmdline.AnalysisManager import AnalysisManager
import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI

from chb.elfformat.ELFSectionHeader import ELFSectionHeader

from chb.graphics.DotCfg import DotCfg

from chb.invariants.InvariantFact import NRVFact
from chb.invariants.NonRelationalValue import NonRelationalValue

from chb.relational.RelationalAnalysis import RelationalAnalysis

import chb.util.dotutil as UD
import chb.util.fileutil as UF
import chb.cmdline.commandutil as UC


def relational_header(xname1: str, xname2: str, header: str) -> str:
    lines: List[str] = []
    lines.append("=" * 80)
    lines.append(
        "||"
        + ("CodeHawk Relational Analysis: " + header).ljust(76)
        + "||")
    lines.append("||" + "  - " + str(xname1).ljust(72) + "||")
    lines.append("||" + "  - " + str(xname2).ljust(72) + "||")
    lines.append("=" * 80)
    return "\n".join(lines)


class XComparison:

    def __init__(self) -> None:
        self._switchpoints: List[str] = []
        self._newcode: List[Tuple[str, str]] = []
        self._report: List[str] = []

    @property
    def switchpoints(self) -> List[str]:
        return self._switchpoints

    def add_switchpoint(self, s: str) -> None:
        self._switchpoints.append(s)

    @property
    def newcode(self) -> List[Tuple[str, str]]:
        return self._newcode

    def add_newcode(self, start: str, endc: str) -> None:
        self._newcode.append((start, endc))

    def add_text(self, s: str) -> None:
        self._report.append(s)

    def __str__(self) -> str:
        return "\n".join(self._report)


def check_hints_for_thumb(hints: List[str]) -> bool:

    for f in hints:
        try:
            with open(f, "r") as fp:
                fuserdata = json.load(fp)
            if "userdata" in fuserdata:
                if "arm-thumb" in fuserdata["userdata"]:
                    return True
        except Exception as e:
            UC.print_error("Error in reading " + f + ": " + str(e))
            exit(1)
    return False


def compare_executable_content(
        path1: str,
        xfile1: str,
        path2: str,
        xfile2: str,
        is_thumb: bool) -> XComparison:
    """Compares the section headers of the second app with those of the first app.

    If additional code is added to one of the sections, it is assumed to be a
    trampoline. If the original application's architecture is Thumb, arm-thumb
    switches are returned, to be added to the user data for disassembly.

    In addition, text is returned that reports the changes.
    """

    xinfo1 = XI.XInfo()
    xinfo1.load(path1, xfile1)
    xinfo2 = XI.XInfo()
    xinfo2.load(path2, xfile2)

    if not (xinfo1.is_elf and xinfo2.is_elf):
        UC.print_error("No support yet for non-elf files")
        exit(1)

    app1 = UC.get_app(path1, xfile1, xinfo1)
    app2 = UC.get_app(path2, xfile2, xinfo2)

    sectionheaders1 = app1.header.sectionheaders
    sectionheaders2 = app2.header.sectionheaders

    xcomparison = XComparison()

    if len(sectionheaders1) > len(sectionheaders2):
        xcomparison.add_text("The patched file has fewer sections")
        for sh1 in sectionheaders1:
            sh2 = app2.header.get_sectionheader_by_name(sh1.name)
            if sh2 is None:
                xcomparison.add_text(
                    "  Section " + sh1.name + " is missing from the patched file")
        return xcomparison

    elif len(sectionheaders1) < len(sectionheaders2):
        for sh2 in sectionheaders2:
            sh1 = app1.header.get_sectionheader_by_name(sh2.name)
            if sh1 is None:
                vaddr2 = sh2.vaddr
                size2 = int(sh2.size, 16)
                xcomparison.add_text(
                    "  Section " + sh2.name + " was added to the patched file:")
                xcomparison.add_text(
                    "    vaddr: "
                    + vaddr2
                    + "; size: "
                    + str(size2)
                    + " ("
                    + hex(size2)
                    + ") bytes")
                if is_thumb:
                    xcomparison.add_switchpoint(vaddr2 + ":T")
        return xcomparison

    xcomparison.add_text(
        " - The number of sections in the patched file is the same as in the original file\n")

    comparison: Dict[
        str, Tuple[Optional[ELFSectionHeader], Optional[ELFSectionHeader]]] = {}
    for sh1 in sectionheaders1:
        name = sh1.name
        if not name in comparison:
            sh2 = app2.header.get_sectionheader_by_name(name)
            comparison[name] = (sh1, sh2)
        else:
            print("Duplicate section name: " + name)
    for sh2 in sectionheaders2:
        if not sh2.name in comparison:
            comparison[sh2.name] = (None, sh2)

    if len(comparison) == len(sectionheaders1):
        xcomparison.add_text(" - All section names match.\n")
    else:
        for (name, (optsh1, optsh2)) in comparison.items():
            if optsh1 is None:
                xcomparison.add_text(
                    "  A new section with name "
                    + name
                    + " was added to the patched file")
            elif optsh2 is None:
                xcomparison.add_text(
                    "  Section with name "
                    + name
                    + " is missing from the patched file")

    for (name, (optsh1, optsh2)) in comparison.items():
        if optsh1 is not None and optsh2 is not None:
            if optsh1.vaddr != optsh2.vaddr:
                xcomparison.add_text(
                    " - The starting address of section "
                    + name
                    + " changed from "
                    + optsh1.vaddr
                    + " in the original file to "
                    + optsh2.vaddr
                    + " in the patched file")

            if optsh1.size != optsh2.size:
                xcomparison.add_text(
                    " - The size of section "
                    + name
                    + " changed from "
                    + optsh1.size
                    + " in the original file to "
                    + optsh2.size
                    + " in the patched file")
            if int(optsh2.size, 16) > int(optsh1.size, 16):
                newvaddr = hex(int(optsh1.vaddr, 16) + int(optsh1.size, 16))
                if is_thumb:
                    xcomparison.add_switchpoint(newvaddr + ":T")
                newvend = hex(int(optsh1.vaddr, 16) + int(optsh2.size, 16))
                xcomparison.add_newcode(newvaddr, newvend)

    return xcomparison


def relational_prepare_command(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname1: str = args.xname1
    xname2: str = args.xname2
    hints: List[str] = args.hints
    headers: List[str] = args.headers
    save_aux_userdata: str = args.save_aux_userdata
    fns_include: List[str] = args.fns_include

    try:
        (path1, xfile1) = UC.get_path_filename(xname1)
        UF.check_analysis_results(path1, xfile1)
        (path2, xfile2) = UC.get_path_filename(xname2)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    is_thumb: bool = check_hints_for_thumb(hints)
    userhints = UC.prepare_executable(path2, xfile2, True, False, hints=hints)

    xcomparison = compare_executable_content(
        path1, xfile1, path2, xfile2, is_thumb)

    print(relational_header(xname1, xname2, "executable sections"))
    print(str(xcomparison))

    newuserdata: Dict[str, Any] = {}

    print("\nAdditions to user data:")
    print("~" * 80)
    if len(xcomparison.switchpoints) > 0:
        print(" - New arm-thumb switch points: " + ", ".join(xcomparison.switchpoints) + "\n")
        newuserdata["arm-thumb"] = xcomparison.switchpoints

    if len(xcomparison.newcode) > 0:
        print(" - New code inserted in the following memory regions:")
        for (x, y) in xcomparison.newcode:
            print("    * From " + x + " to " + y)
            newuserdata["trampolines"] = xcomparison.newcode

    userhints.add_hints(newuserdata)
    userhints.save_userdata(path2, xfile2)

    xinfo2 = XI.XInfo()
    xinfo2.load(path2, xfile2)

    # preprocess c files
    ifilenames: List[str] = []
    headerfilenames = [os.path.abspath(s) for s in headers]
    if len(headers) > 0:
        for f in headerfilenames:
            if os.path.isfile(f):
                ifilename = f[:-2] + ".i"
                ifilenames.append(ifilename)
                gcccmd = ["gcc", "-std=gnu99", "-m32", "-E", "-o", ifilename, f]
                p = subprocess.call(gcccmd, cwd=path2, stderr=subprocess.STDOUT)
                if not (p == 0):
                    UC.print_error("Error in " + str(gcccmd))
                    exit(1)
            else:
                UC.print_error("Header file " + f + " not found")
                exit(1)

    print("=" * 80)
    print("||" + (str(datetime.datetime.now()) + "  ").rjust(76) + "||")
    print("=" * 80)

    print("\n\nAnalyzing patched version with updated user data ...")
    am = AnalysisManager(
        path2,
        xfile2,
        xsize=xinfo2.size,
        arm=True,
        elf=True,
        ifilenames=ifilenames,
        fns_include=fns_include,
        thumb=True)

    try:
        am.analyze()
    except subprocess.CalledProcessError as e:
        print(e.output)
        print(e.args)
        exit(1)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    exit(0)


def relational_compare_functions_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname1: str = args.xname1
    xname2: str = args.xname2
    usermappingfile: Optional[str] = args.usermapping

    try:
        (path1, xfile1) = UC.get_path_filename(xname1)
        UF.check_analysis_results(path1, xfile1)
        (path2, xfile2) = UC.get_path_filename(xname2)
        UF.check_analysis_results(path2, xfile2)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

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

    xinfo1 = XI.XInfo()
    xinfo2 = XI.XInfo()
    xinfo1.load(path1, xfile1)
    xinfo2.load(path2, xfile2)
    app1 = UC.get_app(path1, xfile1, xinfo1)
    app2 = UC.get_app(path2, xfile2, xinfo2)

    relanalysis = RelationalAnalysis(app1, app2, usermapping=usermapping)

    print(relational_header(xname1, xname2, "functions comparison"))
    print(relanalysis.report(False, False))
    print("=" * 80)
    print("||" + (str(datetime.datetime.now()) + "  ").rjust(76) + "||")
    print("=" * 80)

    exit(0)


def relational_compare_function_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname1: str = args.xname1
    xname2: str = args.xname2
    blocks: bool = args.blocks
    details: bool = args.details
    addresses: List[str] = args.addresses
    usermappingfile: Optional[str] = args.usermapping

    try:
        (path1, xfile1) = UC.get_path_filename(xname1)
        UF.check_analysis_results(path1, xfile1)
        (path2, xfile2) = UC.get_path_filename(xname2)
        UF.check_analysis_results(path2, xfile2)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

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

    xinfo1 = XI.XInfo()
    xinfo2 = XI.XInfo()
    xinfo1.load(path1, xfile1)
    xinfo2.load(path2, xfile2)
    app1 = UC.get_app(path1, xfile1, xinfo1)
    app2 = UC.get_app(path2, xfile2, xinfo2)

    relanalysis = RelationalAnalysis(app1, app2, faddrs1=addresses, usermapping=usermapping)

    print(relational_header(
        xname1, xname2, "function comparison of " + ", ".join(addresses)))
    print(relanalysis.report(True, args.details))
    print("=" * 80)
    print("||" + (str(datetime.datetime.now()) + "  ").rjust(76) + "||")
    print("=" * 80)

    exit(0)



def relational_compare_cfgs_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname1: str = args.xname1
    xname2: str = args.xname2
    usermappingfile: Optional[str] = args.usermapping
    showcalls: bool = args.show_calls
    showpredicates: bool = args.show_predicates
    outputfilename: str = args.outputfilename
    fileformat: str = args.format

    print("Visual comparison of the cfgs for " + xname1 + " and " + xname2)

    try:
        (path1, xfile1) = UC.get_path_filename(xname1)
        UF.check_analysis_results(path1, xfile1)
        (path2, xfile2) = UC.get_path_filename(xname2)
        UF.check_analysis_results(path2, xfile2)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

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

    xinfo1 = XI.XInfo()
    xinfo2 = XI.XInfo()
    xinfo1.load(path1, xfile1)
    xinfo2.load(path2, xfile2)
    app1 = UC.get_app(path1, xfile1, xinfo1)
    app2 = UC.get_app(path2, xfile2, xinfo2)

    relanalysis = RelationalAnalysis(app1, app2, usermapping=usermapping)

    functionschanged = relanalysis.functions_changed()
    if len(functionschanged) == 0:
        UC.print_error("No functions changed")
        exit(0)

    dotgraphs: List[DotCfg] = []

    for faddr in functionschanged:
        if faddr in relanalysis.function_mapping:
            fnanalysis = relanalysis.function_analysis(faddr)
            blockschanged = fnanalysis.blocks_changed()
            cfgmatcher = fnanalysis.cfgmatcher
            (dotcfg1, dotcfg2) = cfgmatcher.dot_cfgs(
                blockschanged=blockschanged,
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
        outputfilename,
        fileformat,
        [dotcfg.build() for dotcfg in dotgraphs])

    print(relational_header(xname1, xname2, "control-flow-graph comparison"))
    if os.path.isfile(pdffilename):
        UC.print_info(
            "Control flow graph comparison for "
            + "vulnerable/patched"
            + " has been saved in "
            + pdffilename
            + "\n  - Basic blocks changed or new are shown in orange"
            + "\n  - Basic blocks unchanged (md5-equal) are shown in blue")
    else:
        UC.print_error(
            "Error in converting dot file to pdf")
        exit(1)

    print("=" * 80)
    print("||" + (str(datetime.datetime.now()) + "  ").rjust(76) + "||")
    print("=" * 80)

    exit(0)


def relational_compare_invs_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname1: str = args.xname1
    xname2: str = args.xname2
    usermappingfile: Optional[str] = args.usermapping

    print("Comparison of the invariants for " + xname1 + " and " + xname2)

    try:
        (path1, xfile1) = UC.get_path_filename(xname1)
        UF.check_analysis_results(path1, xfile1)
        (path2, xfile2) = UC.get_path_filename(xname2)
        UF.check_analysis_results(path2, xfile2)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

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

    xinfo1 = XI.XInfo()
    xinfo2 = XI.XInfo()
    xinfo1.load(path1, xfile1)
    xinfo2.load(path2, xfile2)
    app1 = UC.get_app(path1, xfile1, xinfo1)
    app2 = UC.get_app(path2, xfile2, xinfo2)

    relanalysis = RelationalAnalysis(app1, app2, usermapping=usermapping)

    functionschanged = relanalysis.functions_changed()
    if len(functionschanged) == 0:
        UC.print_error("No functions changed")
        exit(0)

    if True:
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

        newblocks: Dict[str, Dict[str, NonRelationalValue]] = {}
        for loc in f2table:
            if loc not in f1table:
                newblocks.setdefault(loc, {})
                f2values = f2table[loc]
                for v2 in f2values:
                    newblocks[loc][v2] = f2values[v2]

        print(relational_header(xname1, xname2, "invariant comparison"))
        counter: int = 0
        print("\nInvariants modified or missing:")
        print("~" * 80)
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

        print("\n\n")
        print("~" * 80)
        print(
            "Invariants not modified: "
            + str(counter)
            + " (in "
            + str(len(f1table))
            + " locations)")
        print("~" * 80)

        print("\nInvariants of newly added blocks:")
        print("~" * 80)
        for loc in sorted(newblocks):
            print("\n" + loc)
            for v in sorted(newblocks[loc]):
                newvalue = newblocks[loc][v]
                print("  " + v.ljust(32) + str(newvalue))

    print("=" * 80)
    print("||" + (str(datetime.datetime.now()) + "  ").rjust(76) + "||")
    print("=" * 80)

    exit(0)
