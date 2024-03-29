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
"""Support functions for the pedata/elfdata subcommand in the command-line interpreter."""

import argparse
import importlib
import json
import os

from typing import (
    Any, Callable, cast, Dict, List, NoReturn, Optional, Tuple, TYPE_CHECKING)

import chb.api.MIPSLinuxSyscalls as SC
import chb.app.AppAccess as AP

from chb.arm.simulation.ARMSimProgramCounter import ARMSimProgramCounter

import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI

from chb.mips.simulation.MIPSimInitializer import MIPSimInitializer
from chb.mips.simulation.MIPSimProgramCounter import MIPSimProgramCounter
from chb.mips.simulation.MIPSimStubs import stubbed_libc_functions, MIPSimStub

from chb.simulation.SimProgramCounter import SimProgramCounter
from chb.simulation.SimSupport import SimSupport
import chb.simulation.SimSymbolicValue as SSV
from chb.simulation.SimulationState import SimulationState, SimModule
import chb.simulation.SimValue as SV
import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.arm.ARMAccess import ARMAccess
    from chb.arm.ARMAssembly import ARMAssembly
    from chb.mips.MIPSAccess import MIPSAccess
    from chb.mips.MIPSAssembly import MIPSAssembly


def simulate_mips_function(
        xname: str,
        app: "MIPSAccess",
        asm: "MIPSAssembly",
        faddr: str,
        stepcount: int = 100,
        libs: Dict[str, Tuple["MIPSAccess", "MIPSAssembly"]] = {},
        support: Optional[str] = None,
        stub_imports: List[str] = [],
        mainargs: List[str] = [],
        optargaddrstr: Optional[str] = None,
        optargstatestr: Optional[str] = None,
        patched_globals: Dict[str, str] = {},
        envptr_addr: Optional[str] = None,
        environment_variables: Optional[List[str]] = None,
        config_value_files: Optional[List[str]] = None) -> NoReturn:

    bigendian = app.header.is_big_endian
    print("big endian " if bigendian else "little endian")

    environmentvars: Dict[str, str] = {}
    if environment_variables is not None:
        for f_envvar in environment_variables:
            if os.path.isfile(f_envvar):
                try:
                    with open(f_envvar, "r") as fp:
                        f_envvar_d = json.load(fp)
                except ValueError as e:
                    raise UF.CHBJSONParseError(f_envvar, e)
                if "key-values" in f_envvar_d:
                    print(
                        "Environment variables read: "
                        + str(len(f_envvar_d["key-values"])))
                    environmentvars.update(f_envvar_d["key-values"])
                else:
                    UC.print_error(
                        "No table with key-value pairs found in "
                        + f_envvar
                        + "\nPlease include key-value mapping with name key-values")
                    exit(1)
            else:
                UC.print_error(
                    "Environment-variables file: "
                    + f_envvar
                    + " not found")

    configvals: Dict[str, str] = {}
    if config_value_files is not None:
        for f_config in config_value_files:
            if os.path.isfile(f_config):
                try:
                    with open(f_config, "r") as fp:
                        f_config_d = json.load(fp)
                except ValueError as e:
                    raise UF.CHBJSONParseError(f_config, e)
                if "key-values" in f_config_d:
                    print("Config values read: "
                          + str(len(f_config_d["key-values"])))
                    configvals.update(f_config_d["key-values"])
                else:
                    UC.print_error(
                        "No table with key-value pairs found in "
                        + f_config
                        + "\nPlease include key-value mapping with name key-values")
                    exit(1)
            else:
                UC.print_error(
                    "Config-values file: "
                    + f_config
                    + " not found")

    stubs: Dict[str, "MIPSimStub"] = stubbed_libc_functions()
    for stubimport in stub_imports:
        importedstubs = importlib.import_module(stubimport)
        print("\nImported user stubs: " + importedstubs.__name__)
        for d in dir(importedstubs):
            if d.endswith("stubs"):
                userstubs: Dict[str, "MIPSimStub"] = getattr(importedstubs, d)()
                stubs.update(userstubs)

    print(
        "Main module "
        + xname
        + ": "
        + app.header.image_base
        + " - "
        + app.max_address)
    mainmodule = SimModule(xname, app, app.header.image_base, app.max_address)

    dynlibs: List[SimModule] = []
    dynasms: Dict[str, "MIPSAssembly"] = {}
    for (libname, (libapp, libasm)) in libs.items():
        print(
            "Lib module "
            + libname
            + ": "
            + libapp.header.image_base
            + " - "
            + app.max_address)
        dynlibs.append(SimModule(
            libname, libapp, libapp.header.image_base, libapp.max_address))
        dynasms[libname] = libasm

    if envptr_addr is not None:
        environmentptr_address: Optional[SSV.SimGlobalAddress] = SSV.mk_global_address(
            int(envptr_addr, 16), modulename=mainmodule.name)
    else:
        environmentptr_address = None

    optargaddr: SV.SimValue = SV.simZero
    optargstate: SV.SimValue = SV.simZero
    if optargaddrstr:
        optargaddr = SSV.mk_global_address(int(optargaddrstr, 16), xname)
    if optargstatestr:
        optargstate = SSV.mk_global_address(int(optargstatestr, 16), xname)

    def default_simsupport() -> SimSupport:
        return SimSupport(
            stepcount=stepcount,
            optargaddr=optargaddr,
            optargstate=optargstate,
            patched_globals=patched_globals,
            environment_variables=environmentvars,
            configvalues=configvals,
            environmentptr_address=environmentptr_address)

    if support:
        importedmodule = importlib.import_module(support)
        print('\nCustom Import: ' + importedmodule.__name__)
        for d in dir(importedmodule):
            print("Module: " + d)
            if importedmodule.__name__.endswith(d):
                print("found module: " + d)
                simsupport = getattr(importedmodule, d)(
                    stepcount=stepcount,
                    optargaddr=optargaddr,
                    optargstate=optargstate,
                    patched_globals=patched_globals,
                    environment_variables=environmentvars,
                    environmentptr_address=environmentptr_address)
                break
        else:
            simsupport = default_simsupport()
    else:
        simsupport = default_simsupport()

    programcounter = MIPSimProgramCounter(
        SSV.mk_global_address(int(faddr, 16), xname))

    initializer = MIPSimInitializer(mainargs)

    simstate = SimulationState(
        faddr,
        mainmodule,
        programcounter,
        siminitializer=initializer,
        dynlibs=dynlibs,
        simsupport=simsupport,
        stubs=stubs,
        bigendian=bigendian)
    currentinstr = asm.instructions[faddr]
    blocktrace: List[Tuple[str, str]] = []
    for i in range(0, simsupport.stepcount):
        try:
            action = currentinstr.simulate(simstate)
            simstate.trace.add(
                str(i).rjust(5) + "  " + str(currentinstr).ljust(48) + str(action))
            simstate.trace.include_delayed()
            if action == "return":
                print("=" * 80)
                print("Simulation ended normally: returning from starting function")
                print("=" * 80)
                print("\nSimulation trace:")
                print("-" * 80)
                print(str(simstate.trace))
                print("\nSimulation state:")
                print("-" * 80)
                print(str(simstate))
                exit(0)

        except SU.CHBSimCallTargetUnknownError as e:
            simstate.trace.add(
                str(i).rjust(5)
                + "**"
                + str(currentinstr).ljust(48)
                + str(e.calltgt))
            pc = simstate.programcounter
            if pc.is_global_address:
                addr = pc.to_hex()
                if addr in asm.instructions:
                    currentinstr = asm.instructions[addr]

        except SU.CHBSimSystemCallException as e:
            syscall = SC.get_mips_linux_syscall(e.syscallindex)
            if syscall in simstate.stubs:
                stub = cast(MIPSimStub, simstate.stubs[syscall])

                # in MIPS register $a3 will be set to 0 or 1 to indicate success
                # ref: https://www.linux-mips.org/wiki/Syscall
                simstate.set_register(e.iaddr, "a3", SV.simZero)

                msg = stub.simulate(e.iaddr, simstate)
                simstate.trace.add(
                    " ".ljust(15) + "syscall:" + syscall + ": " + msg)
                simstate.increment_programcounter()
            else:
                print(str(simstate.trace))
                print(str(simstate))
                print("No stub for syscall: " + syscall)
                exit(1)

        except SU.CHBSimBranchUnknownError as e:
            simstate.trace.add(
                str(i).rjust(5)
                + "**"
                + str(currentinstr).ljust(48)
                + str(e.truetgt)
                + " ("
                + e.msg
                + ")")
            if simstate.simsupport.branch_decision(e.iaddr, simstate):
                simstate.simprogramcounter.set_delayed_programcounter(e.truetgt)
            else:
                simstate.simprogramcounter.set_delayed_programcounter(e.falsetgt)

        except SU.CHBSymbolicExpression as e:
            print(
                "Symbolic expression: "
                + str(e)
                + "; "
                + str(currentinstr).ljust(48))
            print("=" * 80)
            print("")
            print(str(simstate.trace))
            print(str(simstate))
            exit(1)

        except SU.CHBSimExitException as e:
            print("=" * 80)
            print(
                "System exit at address "
                + e.iaddr
                + " with exit value "
                + e.exitvalue)
            print("=" * 80)
            print("\n")
            print(str(simstate.trace))
            print(str(simstate))
            exit(1)

        except SU.CHBSimError as e:
            print("*" * 80)
            print("Error: " + str(e))
            print("*" * 80)
            print("\nSimulation trace")
            print("-" * 80)
            print(str(simstate.trace))
            print("\nSimulation state")
            print("-" * 80)
            print(str(simstate))

            exit(1)

        except Exception as e:
            print("*" * 80)
            print("Exception: " + str(e))
            print("Current instruction: " + str(currentinstr))
            print("*" * 80)
            print("")
            print(str(simstate.trace))
            print(str(simstate))
            exit(1)

        pc = simstate.programcounter
        addr = pc.to_hex()

        try:
            if pc.modulename == xname:
                if addr in asm.instructions:
                    currentinstr = asm.instructions[addr]
                else:
                    raise UF.CHBError(
                        "No instruction found at " + addr + " in " + xname)
            else:
                libasm = dynasms[pc.modulename]
                if addr in libasm.instructions:
                    currentinstr = libasm.instructions[addr]
                else:
                    raise UF.CHBError(
                        "No instruction found at " + addr + " in " + pc.modulename)
        except UF.CHBError as e:
            print("*" * 80)
            print("Exception in fetching next instruction: " + str(e))
            print("*" * 80)
            print("")
            print(str(simstate.trace))
            print(str(simstate))
            exit(1)

    print("\n\nSimulation trace")
    print(str(simstate.trace))

    with open("simstackmemory.json", "w") as fp:
        json.dump(simstate.stackmem.jsonval(), fp, indent=3)

    print("\n\nSimulation state")
    print("=" * 80)
    print(str(simstate))
    exit(0)


def simulate_arm_function(
        xname: str,
        app: "ARMAccess",
        asm: "ARMAssembly",
        faddr: str) -> NoReturn:
    base = app.header.image_base
    mainparticipant = SimModule("app", app, base, app.max_address)
    simstate = SimulationState(
        faddr,
        mainparticipant,
        ARMSimProgramCounter(SSV.mk_global_address(int(faddr, 16), xname)))
    currentinstr = asm.instructions[faddr]
    print(str(currentinstr))

    exit(0)


def unpack_named_strings(l: List[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for s in l:
        ss = s.split(":")
        if len(ss) == 2:
            result[ss[0]] = ss[1]
    return result


def load_mips_lib_file(libxname: str) -> Tuple["MIPSAccess", "MIPSAssembly"]:
    try:
        (libpath, libxfile) = UC.get_path_filename(libxname)
        UF.check_analysis_results(libpath, libxfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    libxinfo = XI.XInfo()
    libxinfo.load(libpath, libxfile)

    libapp = cast("MIPSAccess", UC.get_app(libpath, libxfile, libxinfo))
    libasm = cast("MIPSAssembly", UC.get_asm(libapp))

    return (libapp, libasm)


def simulate_function_cmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    faddr: str = args.faddr
    stepcount: int = args.steps
    libs: List[str] = args.libs
    support: Optional[str] = args.support
    stub_imports: List[str] = args.stub_imports
    mainargs: List[str] = args.mainargs
    optargaddrstr: Optional[str] = args.optargaddr
    optargstatestr: Optional[str] = args.optargstate
    patched_globals: List[str] = args.patched_globals
    envptr_addr: Optional[str] = args.envptr_addr
    environment_variables: Optional[List[str]] = args.environment_variables
    config_values: Optional[List[str]] = args.config_values

    mainargs = [a.strip() for a in mainargs]

    try:
        (path, xfile) = UC.get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    libnames = unpack_named_strings(libs)
    libapps: Dict[str, Tuple["MIPSAccess", "MIPSAssembly"]] = {}
    for (name, libxname) in libnames.items():
        libapps[name] = load_mips_lib_file(libxname)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    print(str(xinfo))

    app = UC.get_app(path, xfile, xinfo)
    asm = UC.get_asm(app)

    if xinfo.is_mips:
        app = cast("MIPSAccess", app)
        asm = cast("MIPSAssembly", asm)
        simulate_mips_function(
            xname,
            app,
            asm,
            faddr,
            stepcount=stepcount,
            libs=libapps,
            support=support,
            stub_imports=stub_imports,
            mainargs=[x.lstrip() for x in mainargs],
            optargaddrstr=optargaddrstr,
            optargstatestr=optargstatestr,
            patched_globals=unpack_named_strings(patched_globals),
            config_value_files=config_values,
            environment_variables=environment_variables,
            envptr_addr=envptr_addr)

    elif xinfo.is_arm:
        app = cast("ARMAccess", app)
        asm = cast("ARMAssembly", asm)
        simulate_arm_function(xname, app, asm, faddr)

    else:
        UC.print_error(
            "Simulation not yet implemented for "
            + app.__class__.__name__)
        exit(1)
