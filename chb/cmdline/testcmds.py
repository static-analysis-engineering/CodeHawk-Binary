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
"""Support functions for the tests command-line interpreter."""

import argparse
import json
import os
import subprocess

from typing import Any, Dict, List, NoReturn, Optional, Tuple, TYPE_CHECKING

import chb.app.AppAccess as AP
import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI

from chb.tests.ELFARMTestCreator import ELFARMTestCreator
from chb.tests.ELFX86TestCreator import ELFX86TestCreator

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppResultFunctionMetrics import AppResultFunctionMetrics
    from chb.app.Function import Function


def analyze_test_case(filename: str) -> int:
    cmdprocessor = UF.get_command_processor()
    cmd: List[str] = ["python3", cmdprocessor, "analyze", filename, "--reset"]
    result = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return result


def check_test_function(
        f: "Function",
        fstats: "AppResultFunctionMetrics",
        testdata: Dict[str, Any]) -> int:
    refinstrs: Dict[str, Any] = testdata["instrs"]
    refstats: Dict[str, str] = testdata["prec"]

    fnstats: Dict[str, str] = {}
    fnstats["sp"] = "{:6.2f}".format(fstats.espp)
    fnstats["reads"] = "{:6.2f}".format(fstats.readsp)
    fnstats["writes"] = "{:6.2f}".format(fstats.writesp)

    for x in refstats:
        if x in fnstats:
            if not fnstats[x] == refstats[x]:
                print("Discrepancy in stats for " + x
                      + ": found: "
                      + fnstats[x]
                      + " expected: "
                      + refstats[x])
                return (-4)
        else:
            print("Missing fnstat: " + x)
            return (-5)

    invariants: Dict[str, List[str]] = {}
    for (s, invs) in f.invariants.items():
        invariants[s] = [str(x) for x in invs]

    for (iaddr, instr) in f.instructions.items():
        if iaddr in refinstrs:
            refinstr = refinstrs[iaddr]
            if not (refinstr["mn"] == instr.mnemonic):
                print("Instruction mnemonic mismatch: "
                      + refinstr["mn"]
                      + " vs "
                      + instr.mnemonic)
                return (-2)
            for inv in refinstr["invs"]:
                if inv not in invariants[iaddr]:
                    print("Invariant " + inv + " missing in function " + f.faddr)
                    return (-3)
    return 0


def check_test_case(filename: str) -> int:
    testdatafile = filename + ".json"

    try:
        with open(testdatafile, "r") as fp:
            testdata = json.load(fp)
    except Exception as e:
        print(str(e))
        return(-1)

    try:
        (path, xfile) = UC.get_path_filename(filename)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = UC.get_app(path, xfile, xinfo)

    for faddr in testdata["functions"]:
        if app.has_function(faddr):
            f = app.function(faddr)
            fstats = app.result_metrics.get_function_metrics(faddr)
            result = check_test_function(f, fstats, testdata["functions"][faddr])
            if result != 0:
                break
        else:
            print("Function " + faddr + " not found in results")
            result = (-1)
            break

    else:
        result = 0

    return result


def test_run(args: argparse.Namespace) -> NoReturn:

    # arguments
    arch: str = args.arch
    fileformat: str = args.fileformat
    suite: str = args.suite
    test: str = args.test

    testfilename = UF.get_test_filename(arch, fileformat, suite, test)
    result = analyze_test_case(testfilename)
    if result != 0:
        print("Error in analysis of " + testfilename)
        exit(result)

    result = check_test_case(testfilename)
    if result != 0:
        print("Discrepancy in analysis results for " + testfilename)
        print("Result: " + str(result))
        exit(result)

    else:
        print("Test successful for " + testfilename)
    exit(result)


def test_runall(args: argparse.Namespace) -> NoReturn:

    # arguments
    arch: Optional[str] = args.arch
    fileformat: Optional[str] = args.fileformat

    errors: Dict[Tuple[str, str, str, str], int] = {}

    def pr(a: str, ff: str, suite: str, n: str, result: int) -> None:
        ptest = a.ljust(6) + ff.ljust(6) + suite.ljust(12) + n
        if result == 0:
            print(" --ok--  " + ptest)
        else:
            print(" --xx--  " + ptest)

    tests = UF.get_tests()
    counter = 0
    for a in sorted(tests):
        if (arch is None) or (arch == a):
            for ff in sorted(tests[a]):
                if (fileformat is None) or (fileformat == ff):
                    for suite in sorted(tests[a][ff]):
                        for test in sorted(tests[a][ff][suite]):
                            testfilename = UF.get_test_filename(
                                a, ff, suite, test, fullnames=True)
                            basename = os.path.basename(testfilename)
                            result = analyze_test_case(testfilename)
                            counter += 1
                            if result != 0:
                                errors[(a, ff, suite, basename)] = result
                                pr(a, ff, suite, basename, result)
                                continue
                            result = check_test_case(testfilename)
                            if result != 0:
                                errors[(a, ff, suite, basename)] = result
                            pr(a, ff, suite, basename, result)
    if len(errors) > 0:
        print("Errors encountered in:")
        for ((a, ff, suite, n), result) in sorted(errors.items()):
            print(
                a.ljust(6)
                + ff.ljust(6)
                + n.ljust(12)
                + suite.ljust(12)
                + ": "
                + str(result))
        exit(1)

    else:
        print("All " + str(counter) + " tests passed.")
        exit(0)


def test_list(args: argparse.Namespace) -> NoReturn:

    # arguments
    arch: Optional[str] = args.arch
    fileformat: Optional[str] = args.fileformat

    tests = UF.get_tests()
    testsdir = UF.get_tests_dir()
    for a in tests:
        if (arch is None) or (arch == a):
            print(a)
            for ff in tests[a]:
                if (fileformat is None) or (fileformat == ff):
                    print("  " + ff)
                    for suite in sorted(tests[a][ff]):
                        print("    " + suite)
                        for test in sorted(tests[a][ff][suite]):
                            testfilename = UF.get_test_filename(
                                a, ff, suite, test, fullnames=True)
                            with open(testfilename) as fp:
                                s = fp.read()
                            print("      " + s.strip("\n"))
    exit(0)


def test_create(args: argparse.Namespace) -> NoReturn:

    # arguments
    arch: str = args.arch
    fileformat: str = args.fileformat
    testnr: str = args.test
    suitenr: str = args.suite
    bytestring: str = args.bytestring

    files: Dict[str, str] = {}

    if arch == "x86" and fileformat == "elf":
        tcx = ELFX86TestCreator(testnr, bytestring, suite=suitenr)
        elfheader = tcx.create_elf_header()
        elfsection = tcx.create_elf_section()
        xinfo = tcx.create_xinfo()

        files["test_" + testnr + "_elf_header.xml"] = elfheader
        files["test_" + testnr + "_section_16.xml"] = elfsection

        UF.save_test_files(arch, fileformat, suitenr, testnr, files, xinfo)

    elif arch == "arm32" and fileformat == "elf":
        tca = ELFARMTestCreator(testnr, bytestring, suite=suitenr)
        elfheader = tca.create_elf_header()
        elfsection = tca.create_elf_section()
        xinfo = tca.create_xinfo()

        files["test_" + testnr + "_elf_header.xml"] = elfheader
        files["test_" + testnr + "_section_16.xml"] = elfsection

        UF.save_test_files(arch, fileformat, suitenr, testnr, files, xinfo)

    else:
        print("At present only x86-elf and arm-elf are supported")

    exit(0)
