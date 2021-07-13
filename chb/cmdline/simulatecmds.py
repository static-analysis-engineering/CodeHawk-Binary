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
"""Support functions for the pedata/elfdata subcommand in the command-line interpreter."""

import argparse
import json

from typing import Any, cast, Dict, NoReturn, Optional, TYPE_CHECKING

import chb.app.AppAccess as AP

from chb.arm.simulation.ARMSimulationState import ARMSimulationState

import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI

from chb.mips.simulation.MIPSimulationState import MIPSimulationState

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.arm.ARMAccess import ARMAccess
    from chb.arm.ARMAssembly import ARMAssembly
    from chb.mips.MIPSAccess import MIPSAccess
    from chb.mips.MIPSAssembly import MIPSAssembly


def simulate_mips_function(
        app: "MIPSAccess",
        asm: "MIPSAssembly",
        faddr: str) -> NoReturn:
    simstate = MIPSimulationState(
        app,
        "app",
        app.header.image_base,
        faddr)
    currentinstr = asm.instructions[faddr]
    for i in range(0, 100):
        try:
            action = currentinstr.simulate(simstate)
            print(str(i).rjust(5) + "  " + str(currentinstr).ljust(48) + str(action))
            pc = simstate.programcounter
            if pc.is_global_address:
                addr = pc.to_hex()
                if addr in asm.instructions:
                    currentinstr = asm.instructions[addr]
        except SU.CHBSimCallTargetUnknownError as e:
            print(
                str(i).rjust(5)
                + "**"
                + str(currentinstr).ljust(48)
                + str(e.calltgt))
            pc = simstate.programcounter
            if pc.is_global_address:
                addr = pc.to_hex()
                if addr in asm.instructions:
                    currentinstr = asm.instructions[addr]
        except SU.CHBSimBranchUnknownError as e:
            print(
                str(i).rjust(5)
                + "**"
                + str(currentinstr).ljust(48)
                + str(e.truetgt))
            pc = cast(SSV.SimGlobalAddress, e.falsetgt)
            if pc.is_global_address:
                addr = pc.to_hex()
                if addr in asm.instructions:
                    currentinstr = asm.instructions[addr]

    exit(0)


def simulate_arm_function(
        app: "ARMAccess",
        asm: "ARMAssembly",
        faddr: str) -> NoReturn:
    simstate = ARMSimulationState(
        app,
        "app",
        app.header.image_base,
        faddr)
    currentinstr = asm.instructions[faddr]
    print(str(currentinstr))

    exit(0)


def simulate_function_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    faddr: str = args.faddr

    try:
        (path, xfile) = UC.get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    print(str(xinfo))

    app = UC.get_app(path, xfile, xinfo)
    asm = UC.get_asm(app)

    if xinfo.is_mips:
        app = cast("MIPSAccess", app)
        asm = cast("MIPSAssembly", asm)
        simulate_mips_function(app, asm, faddr)

    elif xinfo.is_arm:
        app = cast("ARMAccess", app)
        asm = cast("ARMAssembly", asm)
        simulate_arm_function(app, asm, faddr)

    else:
        UC.print_error(
            "Simulation not yet implemented for "
            + app.__class__.__name__)
        exit(1)
