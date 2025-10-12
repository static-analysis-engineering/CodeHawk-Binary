# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs, LLC
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
"""Support functions for the runcmds command-line interpreter."""

import argparse
import json
import os
import subprocess
import sys
import time

from contextlib import contextmanager
from multiprocessing import Pool

from typing import Any, Iterator, cast, Dict, List, NoReturn, Optional, Tuple, TYPE_CHECKING

import chb.app.AppAccess as AP
import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI

if TYPE_CHECKING:
    from chb.arm.ARMAssembly import ARMAssemblyInstruction


def do_cmd(cmd: Tuple[Optional[str], List[str]]) -> Tuple[List[str], int, str]:
    result = subprocess.run(cmd[1], stdout=subprocess.PIPE, stderr=sys.stderr)
    resultcode = result.returncode
    resultoutput = result.stdout.decode("utf-8")
    filename = cmd[0]
    if filename is not None:
        with open(filename, "w") as fp:
            fp.write(resultoutput)
        UC.print_status_update("Output written to " + filename)
    return (cmd[1], resultcode, resultoutput)


@contextmanager
def timing(activity: str) -> Iterator[None]:
    t0 = time.time()
    yield
    UC.print_status_update(
        '\n'
        + ('=' * 80)
        + '\nCompleted '
        + activity
        + ' in '
        + str(time.time() - t0)
        + ' secs'
        + '\n'
        + ('=' * 80))


def run_commands(args: argparse.Namespace) -> NoReturn:

    # arguments
    name: str = args.cname
    maxp: int = args.maxp
    targets: List[str] = args.targets
    showtargets: bool = args.showtargets

    if not (os.path.isfile(name)):
        UC.print_error(
            "Please specify a json file that lists the analysis commands.")
        exit(1)

    try:
        with open(name, "r") as fp:
            cmdsfile = json.load(fp)
    except json.decoder.JSONDecodeError as e:
        UC.print_error("Error in json commands file: " + str(e))
        exit(1)

    if "targets" not in cmdsfile:
        UC.print_error(
            "Please provide a list of targets with analysis arguments.")
        exit(1)

    cmdtargets = cmdsfile["targets"]

    if showtargets:
        print("Targets available:")
        print("-" * 80)
        for tgt in cmdtargets:
            print("  " + tgt)
        print("-" * 80)
        exit(0)

    results: Dict[str, List[Tuple[List[str], int, str]]] = {}

    for tgt in targets:

        UC.print_status_update("Target: " + tgt)
        if tgt not in cmdtargets:
            UC.print_error(
                "Target specified: " + tgt + " not found\n"
                + "Targets available:\n"
                + "\n".join(("  " + tgt) for tgt in sorted(cmdtargets)))
            exit(1)

        tgts = cmdtargets[tgt]

        if "cmd" not in tgts:
            UC.print_error(
                "Please specify a command (with cmd) for target " + tgt)
            exit(1)
        if "instances" not in tgts:
            UC.print_error(
                "Please specify instances for target " + tgt)
            exit(1)

        cmd = tgts["cmd"]
        cmdinstances = tgts["instances"]
        cmdlines: List[Tuple[Optional[str], List[str]]] = []
        for cmdinst in cmdinstances:
            cmdline = (cmdinst.get("output", None), cmd + cmdinst["args"])
            cmdlines.append(cmdline)

        pool = Pool(maxp)
        with timing(tgt):
            results[tgt] = pool.map(do_cmd, cmdlines)

        if "collect" in tgts:
            collectitems = tgts["collect"]
            collecteddata: Dict[str, Dict[str, int]] = {}
            unknowns: Dict[str, Dict[str, int]] = {}
            opcode_distribution: Dict[str, int] = {}
            filenames: List[str] = [
                cmdinst["args"][0] for cmdinst in tgts["instances"]]
            for filename in filenames:
                (path, xfile) = UC.get_path_filename(filename)
                xinfo = XI.XInfo()
                xinfo.load(path, xfile)
                app = UC.get_app(path, xfile, xinfo)
                asm = UC.get_asm(app)
                if "opcode-distribution" in collectitems:
                    opcd: Dict[str, int] = asm.opcode_distribution()
                    for (k, v) in opcd.items():
                        opcode_distribution.setdefault(k, 0)
                        opcode_distribution[k] += v
                if "unknowns" in collectitems and xinfo.is_arm:
                    for instr in asm.unknown_instructions:
                        instr = cast("ARMAssemblyInstruction", instr)
                        if instr.mnemonic == "unknown":
                            hint = instr.unknown_hint()
                            unknowns.setdefault(hint, {})
                            unknowns[hint].setdefault(xfile, 0)
                            unknowns[hint][xfile] += 1

            if "output" in tgts:
                outputfilename = tgts["output"]
                opcode_output: Dict[str, Any] = {}
                opcode_output["name"] = tgt
                opcode_output["opcode-distribution"] = opcode_distribution
                opcode_output["unknowns"] = unknowns
                with open(outputfilename, "w") as fp:
                    json.dump(opcode_output, fp, indent=2, sort_keys=True)
            else:
                print("\nOpcode distribution")
                for (opc, c) in sorted(opcode_distribution.items()):
                    print(str(c).rjust(10) + "  " + opc)
                print("\nUnknowns")
                for (hint, ufiles) in sorted(unknowns.items()):
                    print("\n" + hint)
                    for (f, c) in sorted(ufiles.items()):
                        print("  " + str(c).rjust(5) + "  " + f)

    for tgt in results:
        UC.print_status_update("Results for " + tgt)
        for fresult in results[tgt]:
            status = " ok " if fresult[1] == 0 else "fail"
            UC.print_status_update(status + "  " + " ".join(fresult[0]))
            print(fresult[2])

    exit(0)
