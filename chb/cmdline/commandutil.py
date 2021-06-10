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
import os
import shutil
import subprocess

from typing import (
    Any,
    cast,
    Dict,
    Iterable,
    List,
    Optional,
    NoReturn,
    Set,
    Tuple,
    Sequence,
    TYPE_CHECKING)

from chb.app.AppAccess import AppAccess

from chb.arm.ARMAccess import ARMAccess

from chb.cmdline.AnalysisManager import AnalysisManager

from chb.invariants.InputConstraint import InputConstraint

from chb.mips.MIPSAccess import MIPSAccess
from chb.mips.MIPSCfgPath import MIPSCfgPath
from chb.mips.MIPSFunction import MIPSFunction
from chb.mips.MIPSInstruction import MIPSInstruction

import chb.cmdline.UserHints as UH
import chb.cmdline.XInfo as XI
import chb.graphics.DotCfg as DC
import chb.models.FunctionSummary as F
import chb.models.ModelsAccess as M
import chb.util.DotGraph as DG
import chb.util.dotutil as UD
import chb.util.fileutil as UF
import chb.util.xmlutil as UX

from chb.app.Instruction import Instruction

from chb.x86.X86Access import X86Access

if TYPE_CHECKING:
    import chb.app.Instruction
    import chb.arm.ARMInstruction
    import chb.mips.MIPSInstruction
    import chb.x86.X86Instruction


def print_error(m: str) -> None:
    print("*" * 80)
    print(m)
    print("*" * 80)


def print_info(m: str) -> None:
    print("-" * 80)
    print(m)
    print("-" * 80)


def get_path_filename(xname: str) -> Tuple[str, str]:
    """Returns a path and base filename, and checks for existence."""
    name = os.path.abspath(xname)
    if not os.path.isfile(name):
        raise UF.CHBFileNotFoundError(name)
    path = os.path.dirname(name)
    filename = os.path.basename(name)
    return (path, filename)


def create_xinfo(path: str, xfile: str) -> XI.XInfo:
    """Determines file type using the file utility."""
    xinfo = XI.XInfo()
    xinfo.discover(path, xfile)
    return xinfo


def get_app(path: str, xfile: str, xinfo: XI.XInfo) -> AppAccess:
    arch = xinfo.architecture
    format = xinfo.format
    if arch == "x86":
        return X86Access(path, xfile, fileformat=format, arch=arch)
    elif arch == "mips":
        return MIPSAccess(path, xfile, fileformat=format, arch=arch)
    elif arch == "arm":
        return ARMAccess(path, xfile, fileformat=format, arch=arch)
    else:
        raise UF.CHBError("Archicture " + arch + " not yet supported")


def setup_directories(path: str, xfile: str) -> None:
    """Create the x.ch directories."""
    def makedirc(name: str) -> None:
        if os.path.isdir(name):
            return
        os.makedirs(name)

    makedirc(UF.get_executable_dir(path, xfile))

    # user data
    udir = UF.get_userdata_dir(path, xfile)
    ufndir = os.path.join(udir, "functions")
    makedirc(udir)
    makedirc(ufndir)

    # analysis intermediate
    adir = UF.get_analysis_dir(path, xfile)
    afndir = os.path.join(adir, "functions")
    makedirc(adir)
    makedirc(afndir)

    # results
    rdir = UF.get_results_dir(path, xfile)
    rfndir = os.path.join(rdir, "functions")
    makedirc(rdir)
    makedirc(rfndir)


def setup_user_data(
        path: str,
        xfile: str,
        hints: List[str],
        thumb: List[str],
        md5: str) -> None:
    """Convert hints and command-line options to xml user data."""

    # check for registered options
    if UF.file_has_registered_options(md5):
        cmdline_options = UF.get_file_registered_options(md5)
        if "thumb" in cmdline_options["options"]:
            thumb = cmdline_options["options"]["thumb"]
            print("Use command-line options for " + cmdline_options["name"] + ": ")
            print(" --thumb " + " ".join(thumb))

    # read hints files
    filenames = [os.path.abspath(s) for s in hints]
    if len(filenames) > 0:
        print("use hints files: " + ", ".join(filenames))
    userhints = UH.UserHints(filenames)
    userhints.add_thumb_switch_points(thumb)
    ufilename = UF.get_user_system_data_filename(path, xfile)
    with open(ufilename, "w") as fp:
        fp.write(UX.doc_to_pretty(userhints.to_xml(xfile)))


def prepare_executable(
        path: str,
        xfile: str,
        doreset: bool,
        doresetx: bool,
        hints: List[str] = [],
        thumb: List[str] = []) -> None:
    """Extracts executable and sets up necessary directory structure. """
    xtargz = UF.get_executable_targz_filename(path, xfile)
    xfilename = os.path.join(path, xfile)

    if doresetx:
        if os.path.isfile(xtargz):
            if not os.path.isfile(xfilename):
                raise UF.CHBError("Warning: executable file does not exist. "
                                  + "Not removing the extracted content file.")
            else:
                chdir = UF.get_ch_dir(path, xfile)
                print("Remove " + xtargz)
                os.remove(xtargz)
                shutil.rmtree(chdir)

        else:
            pass

    if os.path.isfile(xtargz):
        chdir = UF.get_ch_dir(path, xfile)
        if os.path.isdir(chdir) and not doreset:
            # everything is in place
            return

        if os.path.isdir(chdir) and (doreset or doresetx):
            # remove existing x.ch directory
            print("Removing " + chdir)
            shutil.rmtree(chdir)

        # unpack existing targz file
        if not UF.unpack_tar_file(path, xfile):
            raise UF.CHBError("Error in unpacking tar.gz file")

        # set up user data from hints files
        xinfo = XI.XInfo()
        xinfo.load(path, xfile)
        setup_directories(path, xfile)
        setup_user_data(path, xfile, hints, thumb, xinfo.md5)
        return

    # executable content has to be extracted
    else:
        xinfo = create_xinfo(path, xfile)

        # check architecture and file format
        if not (xinfo.is_x86
                or xinfo.is_mips
                or xinfo.is_arm):
            raise UF.CHBError("Architecture "
                              + xinfo.architecture
                              + " not supported")
        if not (xinfo.is_pe32 or xinfo.is_elf):
            raise UF.CHBError("File format "
                              + xinfo.format
                              + " not supported")

        # set up directories and user data
        setup_directories(path, xfile)
        setup_user_data(path, xfile, hints, thumb, xinfo.md5)
        xinfo.save(path, xfile)

        # extract executable content
        am = AnalysisManager(
            path,
            xfile,
            mips=xinfo.is_mips,
            arm=xinfo.is_arm,
            elf=xinfo.is_elf)

        print("Extracting executable content into xml ...")
        result = am.extract_executable("-extract")
        if not (result == 0):
            raise UF.CHBError("Error in extracting executable")

        # save the targz file
        am.save_extract()
        return


def analyzecmd(args: argparse.Namespace) -> NoReturn:
    """Invoke analyzer to extract, or disassemble, do full analysis."""

    # arguments
    xname: str = args.xname
    doreset: bool = args.reset
    doresetx: bool = args.resetx
    dodisassemble: bool = args.disassemble
    doextract: bool = args.extract
    verbose: bool = args.verbose
    save_asm: str = args.save_asm
    thumb: List[str] = args.thumb
    preamble_cutoff: int = args.preamble_cutoff
    iterations: int = args.iterations
    hints: List[str] = args.hints  # names of json files

    try:
        (path, xfile) = get_path_filename(xname)
        prepare_executable(path, xfile, doreset, doresetx, hints, thumb)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    if doextract:
        # we are done
        exit(0)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    am = AnalysisManager(
        path,
        xfile,
        mips=xinfo.is_mips,
        arm=xinfo.is_arm,
        elf=xinfo.is_elf,
        thumb=(len(thumb) > 0))

    if dodisassemble:
        try:
            am.disassemble(
                verbose=verbose,
                preamble_cutoff=preamble_cutoff,
                save_asm=save_asm)
        except subprocess.CalledProcessError as e:
            print(e.output)
            print(e.args)
            exit(1)
        except UF.CHBError as e:
            print(str(e.wrap()))
            exit(1)
        exit(0)

    else:
        try:
            am.analyze(
                iterations=iterations,
                verbose=verbose,
                preamble_cutoff=preamble_cutoff)
        except subprocess.CalledProcessError as e:
            print(e.output)
            print(e.args)
            exit(1)
        except UF.CHBError as e:
            print(str(e.wrap()))
            exit(1)
        exit(0)


def results_stats(args: argparse.Namespace) -> NoReturn:
    """Prints out a summary of the analysis results per function."""

    # arguments
    xname: str = str(args.xname)
    nocallees: bool = args.nocallees

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)
    # app = AP.AppAccess(
    #    path, xfile, fileformat=xinfo.format, arch=xinfo.architecture)
    stats = app.result_metrics
    print(stats.header_to_string())
    for f in sorted(stats.get_function_results(),
                    key=lambda f: (f.espp, f.faddr)):
        print(f.metrics_to_string(shownocallees=nocallees))
    print(stats.disassembly_to_string())
    print(stats.analysis_to_string())
    exit(0)


def results_functions(args: argparse.Namespace) -> NoReturn:
    """Prints out annotated assembly listing of all functions."""

    # arguments
    xname: str = str(args.xname)
    functions: List[str] = args.functions
    hash: bool = args.hash
    bytestring: bool = args.bytestring
    bytes: bool = args.bytes
    opcodewidth: int = args.opcodewidth

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)
    if len(functions) == 0:
        fns: Sequence[str] = sorted(app.appfunction_addrs)
    else:
        fns = functions

    for faddr in fns:
        if app.has_function(faddr):
            f = app.function(faddr)
            try:
                if app.has_function_name(faddr):
                    print("\nFunction "
                          + faddr
                          + " ("
                          + app.function_name(faddr)
                          + ")")
                else:
                    print("\nFunction " + faddr)
                print("-" * 80)
                print(f.to_string(
                    bytestring=bytestring,
                    bytes=bytes,
                    hash=hash,
                    sp=True,
                    opcodetxt=True,
                    opcodewidth=opcodewidth))
            except UF.CHBError as e:
                print(str(e.wrap()))
        else:
            print_error("Function " + faddr + " not found")
            continue
    exit(0)


def results_function(args: argparse.Namespace) -> NoReturn:
    """Prints out annotated assembly listing of a function."""

    # arguments
    xname: str = str(args.xname)
    function: str = args.function
    hash: bool = args.hash
    bytestring: bool = args.bytestring
    bytes: bool = args.bytes
    opcodewidth: int = args.opcodewidth

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    if app.has_function(function):
        f = app.function(function)
        try:
            if app.has_function_name(function):
                print("\nFunction "
                      + function
                      + " ("
                      + app.function_name(function)
                      + ")")
            else:
                print("\nFunction " + function)
            print("-" * 80)
            print(f.to_string(
                bytestring=bytestring,
                bytes=bytes,
                hash=hash,
                sp=True,
                opcodetxt=True,
                opcodewidth=opcodewidth))
        except UF.CHBError as e:
            print(str(e.wrap()))
    else:
        print_error("Function " + function + " not found")

    exit(0)


def showcfg(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    faddr: str = args.faddr
    out: str = args.out
    xview: bool = args.view
    xpredicates: bool = args.predicates
    xcalls: bool = args.calls
    xinstr_opcodes: bool = args.instr_opcodes
    xinstr_text: bool = args.instr_text
    xsink: Optional[str] = args.sink
    xsegments: List[str] = args.segments

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)
    if app.has_function(faddr):
        f = app.function(faddr)
        if f is None:
            print_error("Unable to find function " + faddr)
            exit(1)
        graphname = "cfg_" + faddr
        if xsink is not None:
            graphname += "_" + xsink
        if len(xsegments) > 0:
            graphname += "_" + "_".join(xsegments)
        dotcfg = DC.DotCfg(
            graphname,
            f,
            looplevelcolors=["#FFAAAAFF", "#FF5555FF", "#FF0000FF"],
            showpredicates=xpredicates,
            showcalls=xcalls,
            showinstr_opcodes=xinstr_opcodes,
            showinstr_text=xinstr_text,
            mips=xinfo.is_mips,
            sink=xsink,
            segments=xsegments)

        fname = faddr
        if app.has_function_name(faddr):
            fname = fname + " (" + app.function_name(faddr) + ")"

        pdffilename = UD.print_dot(app.path, out, dotcfg.build())

        if os.path.isfile(pdffilename):
            print_info("Control flow graph for "
                       + fname
                       + " has been saved in "
                       + pdffilename)
        else:
            print_error("Error in converting dot file to pdf")
            exit(1)
    else:
        print_error("Function " + faddr + " not found")
        exit(1)
    exit(0)


def showcfgpaths(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    faddr: str = args.faddr
    xcalltarget: Optional[str] = args.calltarget
    xblock: Optional[str] = args.block
    xgraph: Optional[str] = args.graph
    xconditions: bool = args.conditions
    xcalls: bool = args.calls
    xstringconstraints: bool = args.stringconstraints
    xmaxtime: int = args.maxtime

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    if not xinfo.is_mips:
        print_error("Currently only available for mips")
        exit(1)

    app = get_app(path, xfile, xinfo)
    f = cast(MIPSFunction, app.function(faddr))
    if app.has_function(faddr):
        if f is None:
            print_error("Unable to find function " + faddr)
            exit(1)

    if xcalltarget:
        if app.is_unique_app_function_name(xcalltarget):
            calltarget = app.function_address_from_name(xcalltarget)
        else:
            calltarget = xcalltarget
            instrs = f.calls_to_app_function(calltarget)
        if len(instrs) == 0:
            print_error("No calls found to call target: " + calltarget)
            exit(1)
        else:
            blocksinks = {i.mipsblock.baddr: i for i in instrs}
    elif xblock:
        blocksinks = {xblock: cast(MIPSInstruction, f.instruction(xblock))}

    cfgpaths: Dict[str, List[MIPSCfgPath]] = {}  # blocksink -> list of paths
    # cfgconstraints = {} # blocksink -> [ baddr -> condition ]

    for sink in blocksinks:
        cfgpaths[sink] = f.cfg.paths(sink, maxtime=args.maxtime)  # [ MIPSCfgPath ]

    feasiblepaths: Dict[str, List[MIPSCfgPath]] = {}
    infeasiblepaths = 0
    for sink in cfgpaths:
        feasiblepaths[sink] = []
        for p in cfgpaths[sink]:
            if p.is_feasible:
                feasiblepaths[sink].append(p)
            else:
                infeasiblepaths += 1

    feasiblepathcount = sum([len(feasiblepaths[b]) for b in feasiblepaths])
    pathcount = feasiblepathcount + infeasiblepaths

    print('Feasible paths:   ' + str(feasiblepathcount).rjust(4))
    print('Infeasible paths: ' + str(infeasiblepaths).rjust(4))
    print('                  ' + ('-' * 4))
    print('Total:            ' + str(pathcount).rjust(4))
    print('\n\n')

    if xstringconstraints:

        def get_string_constraints(
                paths: Dict[str, List[MIPSCfgPath]]) -> Tuple[
                    Dict[str, Set[str]], Dict[str, Set[str]]]:
            sharedkonstraints = {}
            allkonstraints: Dict[str, Set[str]] = {}
            for sink in paths:
                if not paths[sink]:
                    continue
                pathconstraints0 = [str(c) for c in paths[sink][0].constraints() if c]
                sharedkonstraints[sink] = set(pathconstraints0[:])
                allkonstraints[sink] = set([])
                for path in paths[sink]:
                    pathconstraints = set([str(c) for c in path.constraints() if c])
                    sharedkonstraints[sink] &= pathconstraints
                    allkonstraints[sink] |= pathconstraints
            return (sharedkonstraints, allkonstraints)

        (sharedk, allk) = get_string_constraints(feasiblepaths)
        print("\nShared constraints")
        for sink in sharedk:
            print("Sink: " + str(sink))
            for k in sharedk[sink]:
                print("  " + k)
        if len(allk) > len(sharedk):
            print("\nAll constraints")
            for sink in sorted(allk[sink]):
                print("Sink: " + str(sink))
                for k in sorted(allk[sink]):
                    print("  " + k)

    if xcalls:

        def get_calls(
                paths: Dict[str, List[MIPSCfgPath]]) -> Tuple[
                    Dict[str, Set[Tuple[str, str, str]]],
                    Dict[str, Set[Tuple[str, str, str]]]]:
            sharedcalls: Dict[str, Set[Tuple[str, str, str]]] = {}
            allcalls = {}
            for sink in paths:
                if not paths[sink]:
                    continue
                calls0 = paths[sink][0].block_call_instruction_strings()
                sharedcalls[sink] = set(calls0[:])
                allcalls[sink] = set(calls0[:])
                for path in paths[sink]:
                    calls = set(path.block_call_instruction_strings())
                    sharedcalls[sink] &= calls
                    allcalls[sink] |= calls
            return (sharedcalls, allcalls)

        (sharedc, allc) = get_calls(feasiblepaths)
        print("\nShared calls")
        for sink in sharedc:
            print("Sink: " + str(sink))
            for c in sorted(sharedc[sink]):
                print("  " + c[0] + ":" + c[1] + "  " + c[2])
        if len(allc) > len(sharedc):
            print("\nAll calls")
            for sink in allc:
                print("Sink: " + str(sink))
                for c in sorted(allc[sink]):
                    print("  " + c[0] + ": " + c[1] + "  " + c[2])

    if xgraph:

        def getcolor(n: str) -> Optional[str]:
            loopdepth = len(f.cfg.loop_levels(n))
            if loopdepth == 1:
                return '#FFAAAAFF'
            elif loopdepth == 2:
                return '#FF5555FF'
            elif loopdepth > 2:
                return '#FF0000FF'
            else:
                return None

        def get_edge_label(src: str, dst: str) -> Optional[str]:
            if xconditions:
                c = f.cfg.condition(src, dst)
                if c is not None:
                    return str(c)
                else:
                    return None
            else:
                return None

        def get_node_label(n: str) -> Optional[str]:
            blocktxt = str(n)
            if xcalls:
                basicblock = f.block(str(n))
                callinstrs = basicblock.call_instructions
                pcallinstrs = [i.annotation for i in callinstrs]
                if len(callinstrs) > 0:
                    blocktxt = (
                        blocktxt
                        + "\\n"
                        + "\\n".join(pcallinstrs))
            return blocktxt

        dotgraph = DG.DotGraph(xgraph)
        paths: List[MIPSCfgPath] = sum(cfgpaths.values(), [])
        for p in paths:
            for i in range(len(p.path) - 1):
                dotgraph.add_node(
                    p.path[i],
                    labeltxt=get_node_label(p.path[i]),
                    color=getcolor(p.path[i]))
                dotgraph.add_node(
                    p.path[i+1],
                    labeltxt=get_node_label(p.path[i+1]),
                    color=getcolor(p.path[i+1]))
                dotgraph.add_edge(
                    p.path[i],
                    p.path[i+1],
                    labeltxt=get_edge_label(p.path[i], p.path[i+1]))

        pdffilename = UD.print_dot(path, xfile, dotgraph)
        print('~' * 80)
        print('Restricted cfg for ' + xfile + ' has been saved in '
              + pdffilename)
        print('~' * 80)

    exit(0)


def show_expr_table(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    faddr: str = args.faddr

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)
    if app.has_function(faddr):
        f = app.function(faddr)
        if f is None:
            print_error("Unable to find function " + faddr)
            exit(1)

        print("Expressions found in function " + faddr)
        print("=" * 80)
        print(f.xprdictionary.xpr_table_to_string())
        print("=" * 80)
    else:
        print("*" * 80)
        print("Function " + faddr + " not found")
        print("Please specify function as a valid hex address.")
        print("To see a list of functions and their addresses analyzed use:")
        print("  > chkx show stats " + xname)
        print("*" * 80)

    exit(0)


def show_invariant_table(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    faddr: str = args.faddr

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)
    if app.has_function(faddr):
        f = app.function(faddr)
        if f is None:
            print_error("Unable to find function " + faddr)
            exit(1)

        print(f.invdictionary.invariant_fact_table_to_string())

        print("Location invariants")
        print("-------------------")
        invariants = f.invariants
        for loc in sorted(invariants):
            print(loc)
            for fact in invariants[loc]:
                print("  " + str(fact))

    else:
        print("*" * 80)
        print("Function " + faddr + " not found")
        print("Please specify function as a valid hex address.")
        print("To see a list of functions and their addresses analyzed use:")
        print("  > chkx show stats " + xname)
        print("*" * 80)

    exit(0)


def show_vars_table(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    faddr: str = args.faddr

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)
    if app.has_function(faddr):
        f = app.function(faddr)
        if f is None:
            print_error("Unable to find function " + faddr)
            exit(1)

        print(f.xprdictionary.var_table_to_string())

    else:
        print("*" * 80)
        print("Function " + faddr + " not found")
        print("Please specify function as a valid hex address.")
        print("To see a list of functions and their addresses analyzed use:")
        print("  > chkx show stats " + xname)
        print("*" * 80)

    exit(0)
