#!/usr/bin/env python3
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
"""Support functions for the command-line interpreter."""

import argparse
from chb.elfformat.ELFHeader import ELFHeader
from chb.peformat.PEHeader import PEHeader
import json
import os
import shutil
import subprocess

from typing import (
    Any,
    Callable,
    Type,
    Union,
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

import xml.etree.ElementTree as ET

from chb.app.AbstractSyntaxTree import VariableNamesRec

from chb.app.ASTUtil import InstrUseDef, UseDef

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree
from chb.app.AppAccess import AppAccess
from chb.app.Assembly import Assembly
from chb.app.ASTNode import ASTStmt, ASTExpr, ASTVariable
from chb.app.Callgraph import CallgraphNode

import chb.app.ASTDeserializer as D

from chb.arm.ARMAccess import ARMAccess
from chb.arm.ARMAssembly import ARMAssembly

from chb.bctypes.BCFiles import BCFiles

from chb.cmdline.AnalysisManager import AnalysisManager

from chb.invariants.InputConstraint import InputConstraint
from chb.invariants.XXpr import XXpr

from chb.mips.MIPSAccess import MIPSAccess
from chb.mips.MIPSAssembly import MIPSAssembly
from chb.mips.MIPSCfgPath import MIPSCfgPath
from chb.mips.MIPSFunction import MIPSFunction
from chb.mips.MIPSInstruction import MIPSInstruction

from chb.power.PowerAccess import PowerAccess

import chb.cmdline.XInfo as XI
import chb.graphics.DotCfg as DC
from chb.graphics.DotCallgraph import DotCallgraph
import chb.models.FunctionSummary as F
import chb.models.ModelsAccess as M

from chb.userdata.UserHints import UserHints

from chb.util.Config import Config

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


def get_format(name: str) -> Union[Type[PEHeader], Type[ELFHeader]]:
    if name == "elf":
        return ELFHeader
    if name in ("pe", "pe32"):
        return PEHeader
    raise ValueError("Unknown format name: %s" % name)


def get_app(path: str, xfile: str, xinfo: XI.XInfo) -> AppAccess:
    arch = xinfo.architecture
    format = get_format(xinfo.format)
    if arch == "x86":
        return X86Access(path, xfile, fileformat=format)
    elif arch == "mips":
        return MIPSAccess(path, xfile, fileformat=format)
    elif arch == "arm":
        return ARMAccess(path, xfile, fileformat=format)
    elif arch == "powerpc":
        return PowerAccess(path, xfile, fileformat=format)
    else:
        raise UF.CHBError("Archicture " + arch + " not yet supported")


def get_asm(app: AppAccess) -> Assembly:
    if isinstance(app, MIPSAccess):
        app = cast(MIPSAccess, app)
        return MIPSAssembly(app, UF.get_mips_asm_xnode(app.path, app.filename))
    elif isinstance(app, ARMAccess):
        return ARMAssembly(app, UF.get_arm_asm_xnode(app.path, app.filename))
    else:
        print_error("Simulation not yet supported for " + app.__class__.__name__)
        exit(1)


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

    userhints = UserHints()

    # check for registered userdata
    if UF.file_has_registered_userdata(md5):
        print("Use registered userdata.")
        userdata = UF.get_file_registered_userdata(md5)
        userhints.add_hints(userdata)

    # check for registered options
    if UF.file_has_registered_options(md5):
        cmdline_options = UF.get_file_registered_options(md5)
        if "thumb" in cmdline_options["options"]:
            thumb = cmdline_options["options"]["thumb"]
            print("Use command-line options for " + cmdline_options["name"] + ": ")
            print(" --thumb " + " ".join(thumb))
            armuserdata: Dict[str, List[str]] = {}
            armuserdata["arm-thumb"] = thumb
            userhints.add_hints(armuserdata)

    # check direct command-line options
    if len(thumb) > 0:
        print("Use command-line options for thumb: ")
        print(" --thumb " + " ".join(thumb))
        cmdarmuserdata: Dict[str, List[str]] = {}
        cmdarmuserdata["arm-thumb"] = thumb
        userhints.add_hints(cmdarmuserdata)

    # read hints files
    os.chdir(path)
    filenames = [os.path.abspath(s) for s in hints]
    if len(filenames) > 0:
        print("use hints files: " + ", ".join(filenames))
        for f in filenames:
            try:
                with open(f, "r") as fp:
                    fuserdata = json.load(fp)
                if "userdata" in fuserdata:
                    userhints.add_hints(fuserdata["userdata"])
                else:
                    print_error(
                        "Expected to find userdata in " + f)
                    exit(1)
            except Exception as e:
                print_error(
                    "Error in reading " + f + ": " + str(e))
                exit(1)

    userhints.save_userdata(path, xfile)


def prepare_executable(
        path: str,
        xfile: str,
        doreset: bool,
        doresetx: bool,
        verbose: bool = False,
        hints: List[str] = [],
        thumb: List[str] = []) -> None:
    """Extracts executable and sets up necessary directory structure. """
    xtargz = UF.get_executable_targz_filename(path, xfile)
    xfilename = os.path.join(path, xfile)

    if doresetx:
        if os.path.isfile(xtargz):
            if not os.path.isfile(xfilename):
                raise UF.CHBError(
                    "Warning: executable file does not exist. "
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
                or xinfo.is_powerpc
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
            xinfo.size,
            mips=xinfo.is_mips,
            arm=xinfo.is_arm,
            power=xinfo.is_powerpc,
            elf=xinfo.is_elf)

        print("Extracting executable content into xml ...")
        result = am.extract_executable(
            chcmd="-extract", verbose=verbose)
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
    deps: List[str] = args.thirdpartysummaries
    so_libraries: List[str] = args.so_libraries
    skip_if_asm: bool = args.skip_if_asm
    skip_if_metrics: bool = args.skip_if_metrics
    hints: List[str] = args.hints  # names of json files
    headers: List[str] = args.headers   # names of c files
    fns_no_lineq: List[str] = args.fns_no_lineq  # function hex addresses
    fns_exclude: List[str] = args.fns_exclude  # function hex addresses
    fns_include: List[str] = args.fns_include  # function hex addresses

    try:
        (path, xfile) = get_path_filename(xname)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    if skip_if_asm and UF.has_asm_results(path, xfile):
        # we have what we need
        print("Skip disassembly of " + xname)
        exit(0)

    if skip_if_metrics and UF.has_analysis_results(path, xfile):
        # we have what we need
        print("Skip analysis of " + xname)
        exit(0)

    try:
        prepare_executable(
            path,
            xfile,
            doreset,
            doresetx,
            verbose=verbose,
            hints=hints,
            thumb=thumb)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    if doextract:
        # we are done
        exit(0)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    # preprocess c files
    ifilenames: List[str] = []
    if len(headers) > 0:
        for f in headers:
            if os.path.isfile(f):
                ifilename = f[:-2] + ".i"
                ifilenames.append(ifilename)
                gcccmd = ["gcc", "-std=gnu99", "-m32", "-E", "-o", ifilename, f]
                p = subprocess.call(gcccmd, cwd=path, stderr=subprocess.STDOUT)
                if not (p == 0):
                    print_error("Error in " + str(gcccmd))
                    exit(1)

    am = AnalysisManager(
        path,
        xfile,
        xinfo.size,
        mips=xinfo.is_mips,
        arm=xinfo.is_arm,
        power=xinfo.is_powerpc,
        elf=xinfo.is_elf,
        deps=deps,
        so_libraries=so_libraries,
        ifilenames=ifilenames,
        fns_no_lineq=fns_no_lineq,
        fns_exclude=fns_exclude,
        fns_include=fns_include,
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

    stats = app.result_metrics
    print(stats.header_to_string())
    for f in sorted(stats.get_function_results(),
                    key=lambda f: (f.espp, f.faddr)):
        print(f.metrics_to_string(shownocallees=nocallees))
    print(stats.disassembly_to_string())
    print(stats.analysis_to_string())
    exit(0)


def results_callgraph(args: argparse.Namespace) -> NoReturn:
    """Generates a callgraph in dot."""

    # arguments
    xname: str = args.xname
    out: str = args.out
    hidelibs: bool = args.hide_lib_functions
    hideunknowns: bool = args.hide_unknown_targets
    reverse: bool = args.reverse
    align: str = args.align
    sources: List[str] = args.sources
    sinks: List[str] = args.sinks

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    def getcolor(node: CallgraphNode) -> str:
        if node.is_lib_node:
            return "green"
        elif node.is_unknown_tgt:
            return "yellow"
        elif node.is_call_back_table_node or node.is_tagged_app_node:
            return "orange"
        else:
            return "lightblue"

    def nodefilter(node: CallgraphNode) -> bool:
        if hidelibs and node.is_lib_node:
            return False
        elif hideunknowns and node.is_unknown_tgt:
            return False
        else:
            return True

    callgraph = app.callgraph()
    if len(sources) > 0:
        callgraph = callgraph.constrain_sources(sources)
    if len(sinks) > 0:
        callgraph = callgraph.constrain_sinks(sinks)

    def sameleftrank(node: CallgraphNode) -> bool:
        return callgraph.is_root_node(node.name)

    def samerightrank(node: CallgraphNode) -> bool:
        return callgraph.is_sink_node(node.name)

    samerank: List[Callable[[CallgraphNode], bool]] = []
    if align == "left":
        samerank = [sameleftrank]
    elif align == "right":
        samerank = [samerightrank]
    elif align == "both":
        samerank = [sameleftrank, samerightrank]

    dotgraph = DotCallgraph(
        "callgraph",
        callgraph,
        reverse=reverse,
        getcolor=getcolor,
        nodefilter=nodefilter,
        samerank=samerank).to_dotgraph()
    pdffilename = UD.print_dot(app.path, out, dotgraph)

    if os.path.isfile(pdffilename):
        print_info("Call graph for " + xname + " has been saved in " + pdffilename)

    else:
        print_error("Error in converting dot file to pdf")
        exit(1)

    exit(0)


def results_globalvars(args: argparse.Namespace) -> NoReturn:
    """Prints out global variables being read and written per function."""

    # arguments
    xname: str = str(args.xname)

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)
    print("Base address: " + app.header.image_base)
    print("Max address: " + app.header.max_address_space)

    (lhsglobals, rhsglobals) = app.global_refs()

    lhsdir: Dict[str, Dict[str, int]] = {}
    rhsdir: Dict[str, Dict[str, int]] = {}

    print("Global variables that get assigned:")
    print("-----------------------------------")
    for faddr in sorted(lhsglobals):
        print("Function " + faddr)
        for v in lhsglobals[faddr]:
            print("  " + str(v))
            lhsdir.setdefault(str(v), {})
            lhsdir[str(v)].setdefault(faddr, 0)
            lhsdir[str(v)][faddr] += 1

    for gv in sorted(lhsdir):
        print("\nGlobal variable " + gv)
        for faddr in sorted(lhsdir[gv]):
            print("  " + faddr + ": " + str(lhsdir[gv][faddr]))

    print("\nGlobal variables that are referenced:")
    print("---------------------------------------")
    for faddr in sorted(rhsglobals):
        print("Function " + faddr)
        for x in rhsglobals[faddr]:
            print("  " + str(x))
            rhsdir.setdefault(str(x), {})
            rhsdir[str(x)].setdefault(faddr, 0)
            rhsdir[str(x)][faddr] += 1

    for gx in sorted(rhsdir):
        print("\nGlobal expression " + gx)
        for faddr in sorted(rhsdir[gx]):
            print("  " + faddr + ": " + str(rhsdir[gx][faddr]))

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
            try:
                f = app.function(faddr)
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
            # except Exception as e:
            #    print(str(e))
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


def results_invariants(args: argparse.Namespace) -> NoReturn:
    """Prints out a list of invariants for a function per location."""

    # arguments
    xname: str = str(args.xname)
    function: str = args.function
    xinclude: List[str] = args.include
    xexclude: List[str] = args.exclude

    def in_include(f: str) -> bool:
        for s in xinclude:
            if s in f:
                return True
        return False

    def in_exclude(f: str) -> bool:
        for s in xexclude:
            if s in f:
                return True
        return False

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
        if f is None:
            print_error("Unable to find function " + function)
            exit(1)

        invariants = f.invariants
        for loc in sorted(invariants):
            if any(f.is_unreachable for f in invariants[loc]):
                print(loc + ": unreachable")
            else:
                print(loc)
                for fact in invariants[loc]:
                    if (
                            fact.is_initial_var_disequality
                            or fact.is_initial_var_equality):
                        continue
                    pfact = str(fact)
                    if len(xinclude) == 0:
                        if in_exclude(pfact):
                            continue
                        else:
                            print("  " + pfact)
                    else:
                        if (in_include(pfact) and not in_exclude(pfact)):
                            print("  " + pfact)
    exit(0)


def results_branchconditions(args: argparse.Namespace) -> NoReturn:
    """Prints out the conditions of conditional branches."""

    # arguments
    xname: str = str(args.xname)
    function: str = args.function

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    if xinfo.is_x86:
        print_info("Branch conditions have not been implemented yet for x86")
        exit(0)

    app = get_app(path, xfile, xinfo)

    if app.has_function(function):
        f = app.function(function)
        if f is None:
            print_error("Unable to find function " + function)
            exit(1)

        branchconditions = f.branchconditions
        print(
            "block".ljust(12)
            + "instr".ljust(12)
            + "opcode".ljust(32)
            + "branch condition")
        print("-" * 80)
        for (bc, bci) in sorted(branchconditions.items()):
            print(
                bc.ljust(12)
                + bci.iaddr.ljust(12)
                + bci.opcodetext.ljust(32)
                + bci.annotation)

    exit(0)


def results_extract(args: argparse.Namespace) -> NoReturn:
    """Saves a table as a json file of records."""

    # arguments
    xname: str = str(args.xname)
    addr: str = str(args.addr)
    xout: str = str(args.out)
    size: int = int(args.size)
    structure: List[str] = args.structure
    stringtables: List[str] = args.stringtables
    structtable: bool = args.structtable

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    if not xinfo.is_elf:
        print("File is not an ELF file: " + xinfo.format)
        exit(1)

    app = get_app(path, xfile, xinfo)
    elfheader = app.header

    iaddr = int(addr, 16)
    sectionindex = elfheader.get_elf_section_index(iaddr)
    if sectionindex is None:
        print_error("Address not found in elf section: " + addr)
        exit(1)

    table: List[List[str]] = []
    little_endian = not elfheader.is_big_endian

    if structtable:
        if addr in app.structtables.structtables:
            sttable = app.structtables.structtables[addr]
            print(str(sttable))
            outfilename = xout + ".json"
            with open(outfilename, "w") as fp:
                json.dump(sttable.serialize(), fp)
            exit(0)
        else:
            print_error("Structtable address not found: " + addr)
            exit(1)

    if stringtables:
        for addr in stringtables:
            iaddr = int(addr, 16)
            sectionindex = elfheader.get_elf_section_index(iaddr)
            if sectionindex is None:
                print_error("Address not found in elf section: " + addr)
            stable: List[str] = []
            while True:
                data = elfheader.get_doubleword_value(
                    sectionindex, iaddr, little_endian=little_endian)
                iaddr += 4
                if data == 0:
                    break
                else:
                    strindex = elfheader.get_elf_section_index(data)
                    strdata = elfheader.get_string(strindex, data)
                    stable.append(strdata)
            table.append(stable)

    else:
        while True:
            r: List[str] = []
            for t in structure:
                data = elfheader.get_doubleword_value(
                    sectionindex, iaddr, little_endian=little_endian)
                iaddr += 4
                if data == 0:
                    r.append("0")
                    continue
                elif t == "str":
                    strindex = elfheader.get_elf_section_index(data)
                    if strindex is None:
                        print_error("String address not found: " + hex(data))
                    strdata = elfheader.get_string(strindex, data)
                    r.append(strdata)
                elif t == "int":
                    r.append(str(data))
                else:
                    r.append(hex(data))
            if all(e == "0" for e in r):
                break
            else:
                table.append(r)

    result: Dict[str, Any] = {}
    result["file"] = xfile
    result["structure"] = structure
    result["start-address"] = addr
    result["records"] = len(table)
    result["table"] = table

    outfilename = xout + ".json"
    with open(outfilename, "w") as fp:
        json.dump(result, fp, indent=3)

    print("Found " + str(len(table)) + " records")
    exit(0)


def results_fileio(args: argparse.Namespace) -> NoReturn:
    """Prints out a list of files that are opened and closed."""

    # arguments
    xname: str = str(args.xname)

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    results: Dict[str, Dict[str, int]] = {}
    callinstrs = app.call_instructions()
    for faddr in callinstrs:
        for (baddr, instrs) in callinstrs[faddr].items():
            fn = app.function(faddr)
            for instr in instrs:
                ctgt = str(instr.call_target)
                if ctgt in ["fopen", "fopen64"]:
                    results.setdefault(ctgt, {})
                    callargs = instr.call_arguments
                    if len(args) > 1:
                        results[ctgt].setdefault(str(callargs[0]), 0)
                        results[ctgt][str(callargs[0])] += 1

    print("\nFiles opened by " + xname + ":")
    print("-" * 80)
    for tgt in results:
        for c in sorted(results[tgt]):
            print(str(results[tgt][c]).rjust(5) + "  " + c)

    exit(0)


def extract_function_edges(edges: List[str]) -> Dict[str, List[Tuple[str, str]]]:
    result: Dict[str, List[Tuple[str, str]]] = {}
    for x in edges:
        if ":" in x:
            edge = x.split(":")
            if len(edge) == 3:
                result.setdefault(edge[0], [])
                result[edge[0]].append((edge[1], edge[2]))
            else:
                print_error(
                    "Error in format of edge specification: "
                    + x
                    + "; Edge has " + str(len(edge)) + " components: "
                    + ", ".join(edge)
                    + ". Expected 3 items: faddr:src:tgt")
                exit(1)
        else:
            print_error(
                "Error in format of edge specification: "
                + x
                + "; Expected to find two colon separators: faddr:src:tgt")
            exit(1)
    return result


def showast(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    decompile: bool = args.decompile
    exclude: List[str] = args.exclude
    ignore_return_value: List[str] = args.ignore_return_value
    functions: List[str] = args.functions
    hints: List[str] = args.hints  # names of json files
    remove_edges: List[str] = args.remove_edges
    add_edges: List[str] = args.add_edges
    verbose: bool = args.verbose
    available_exprs: List[str] = args.show_available_exprs

    if (not decompile) and len(functions) == 0:
        print_error(
            "Please specify at least one function address\n"
            + "with the --functions command-line option.")
        exit(1)

    rmedges: Dict[str, List[Tuple[str, str]]] = {}
    adedges: Dict[str, List[Tuple[str, str]]] = {}
    if len(remove_edges) + len(add_edges) > 0:
        rmedges = extract_function_edges(remove_edges)
        adedges = extract_function_edges(add_edges)

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    # read hints files
    os.chdir(path)
    userhints = UserHints(toxml=False)
    filenames = [os.path.abspath(s) for s in hints]
    if len(filenames) > 0:
        print("use hints files: " + ", ".join(filenames))
        for filename in filenames:
            try:
                with open(filename, "r") as fp:
                    fuserdata = json.load(fp)
                if "userdata" in fuserdata:
                    userhints.add_hints(fuserdata["userdata"])
                else:
                    print_error(
                        "Expected to find userdata in " + filename)
                    exit(1)
            except Exception as e:
                print_error(
                    "Error in reading " + filename + ": " + str(e))
                exit(1)

    if UF.file_has_registered_userdata(xinfo.md5):
        print("Use registered userdata.")
        userdata = UF.get_file_registered_userdata(xinfo.md5)
        userhints.add_hints(userdata)

    jsonfilenames: Dict[str, str] = {}

    app = get_app(path, xfile, xinfo)

    excluded: int = 0
    if decompile:
        for (faddr, fn) in app.functions.items():
            if faddr in exclude or fn.cfg.has_loops():
                excluded += 1
                continue
            functions.append(faddr)

    functioncount: int = 0
    failedfunctions: int = 0
    opc_unsupported: Dict[str, int] = {}    # instr mnemonic -> count

    for faddr in functions:
        print("========= Function " + faddr + " ================")
        if app.has_function(faddr):
            f = app.function(faddr)
            if f is None:
                print_error("Unable to find function " + faddr)
                continue

            fnrmedges: List[Tuple[str, str]] = []
            fnadedges: List[Tuple[str, str]] = []
            if faddr in rmedges:
                fnrmedges = rmedges[faddr]
                print("Remove " + str(len(fnrmedges)) + " edge(s) from cfg")                
            if faddr in adedges:
                fnadedges = adedges[faddr]
                print("Add " + str(len(fnadedges)) + " edge(s) to cfg")                
            if len(fnrmedges) + len(fnadedges) > 0:
                f.cfg.modify_edges(fnrmedges, fnadedges)

            fname = faddr
            if app.has_function_name(faddr):
                fname = app.function_name(faddr)
            else:
                fname = "sub_" + faddr[2:]

            variablenames: VariableNamesRec = userhints.variable_names()
            symbolicaddrs: Dict[str, str] = userhints.symbolic_addresses()
            revsymbolicaddrs = {v: k for (k, v) in symbolicaddrs.items()}
            revfunctionnames = userhints.rev_function_names()

            astree = AbstractSyntaxTree(
                faddr,
                fname,
                variablenames=variablenames,
                symbolicaddrs=symbolicaddrs,
                ignore_return_value=ignore_return_value,
                callingconvention=xinfo.architecture)
            gvars: List[ASTVariable] = []

            if app.bcfiles.has_functiondef(fname):
                fdef = app.bcfiles.functiondef(fname)
                astree.set_functiondef(fdef)
                astree.set_function_prototype(fdef.svinfo)

            for vinfo in app.bcfiles.globalvars:
                vname = vinfo.vname
                if vname in revsymbolicaddrs:
                    gaddr = int(revsymbolicaddrs[vname], 16)
                elif vname in revfunctionnames:
                    gaddr = int(revfunctionnames[vname], 16)
                else:
                    gaddr = 0
                gvars.append(
                    astree.mk_global_variable(
                        vname, vinfo.vtype, globaladdress=gaddr))

            try:
                ast = f.ast(astree)
            except UF.CHBError as e:
                print("=" * 80)
                print("AST generation is still experimental with limited support.")
                print(
                    "The following is not yet supported for function "
                    + fname
                    + " ("
                    + faddr
                    + ")")
                print(" -- " + str(e))
                print('-' * 80)
                failedfunctions += 1
                continue
            except Exception as e:
                print("*" * 80)
                print(
                    "Error in AST generation in function: "
                    + fname
                    + " ("
                    + faddr
                    + ")")
                print(str(e))
                print("*" * 80)
                failedfunctions += 1
                continue

            unsupported = astree.unsupported_instructions
            if len(unsupported) > 0:
                print("=" * 80)
                print("AST generation is still experimental with limited support.")
                print(
                    "We don't yet support the following instructions in "
                    + fname
                    + " ("
                    + faddr
                    + ")")
                print('-' * 80)
                for m in unsupported:
                    opc_unsupported.setdefault(m, 0)
                    opc_unsupported[m] += len(unsupported)
                    print(m)
                    for instr in unsupported[m]:
                        print("  " + instr)
                print('-' * 80)
                failedfunctions += 1
                continue

            ast = cast(ASTStmt, ast)

            # defs = ast.defs()
            addresstaken = ast.address_taken()
            callees = ast.callees()
            storagerecords = astree.storage_records()

            macronames: Dict[int, str] = {}
            for s in symbolicaddrs:
                macronames[int(s, 16)] = symbolicaddrs[s]

            for i in range(0, 5):
                instr_usedefs_e = InstrUseDef()
                usedefs = UseDef({})
                usedefs = ast.usedefs_x(usedefs, addresstaken, instr_usedefs_e)
                ast = ast.transform_instr_subx(instr_usedefs_e)

            spans = astree.spans

            if verbose:
                print("\nSpans")
                print("-" * 80)
                for span in spans:
                    print(str(span))
                print("=" * 80)

            if verbose:
                print(ast.to_c_like(sp=3))

            spanmap: Dict[int, str] = {}
            for spanrec in spans:
                spanid = cast(int, (spanrec["id"]))
                spans_at_id = cast(List[Dict[str, Any]], spanrec["spans"])
                spanmap[spanid] = spans_at_id[0]["base_va"]

            availablexprs: Dict[str, List[Tuple[int, str, str, str]]] = {}
            for instrlabel in instr_usedefs_e.instrdefs:
                if instrlabel in spanmap:
                    addr = spanmap[instrlabel]
                    availablexprs[addr] = cast(List[Tuple[int, str, str, str]], [])
                    for (v, d) in instr_usedefs_e.get(instrlabel).defs.items():
                        lvaltype = d[1].ctype
                        if lvaltype is None:
                            lvaltype = d[2].ctype
                        availablexprs[addr].append((d[0], v, d[2].to_c_like(), str(lvaltype)))

            if verbose:
                print("\nAvailable expressions")
                print("-" * 80)
                for s in sorted(availablexprs):
                    print(s)
                    for r in availablexprs[s]:
                        print("  " + str(r))
                print("=" * 80)

            instr_live_x: Dict[int, Set[str]] = {}
            live_x = ast.live_e(set([]), instr_live_x)

            mapping: Dict[int, int] = {}
            astreduced = ast.reduce(mapping, instr_live_x, macronames)

            astreduced = astree.rewrite_stmt(astreduced)

            revmapping: Dict[int, List[int]] = {}
            for (i, j) in mapping.items():
                revmapping.setdefault(j, [])
                revmapping[j].append(i)

            functioncount += 1
            print("")
            if astree.has_function_prototype():
                print(str(astree.function_prototype()) + "{")
            else:
                print("int " + fname + "(?)")
            print(astreduced.to_c_like(sp=3))
            print("}\n")

            if not decompile:

                ast_output: Dict[str, Any] = {}
                ast_output["functions"] = astfunctions = []
                astfunction: Dict[str, Any] = {}
                if app.has_function_name(faddr):
                    astfunction["name"] = app.function_name(faddr)
                astfunction["va"] = faddr
                astfunction["assembly-ast"] = {}
                astfunction["assembly-ast"]["nodes"] = ast.serialize()
                astfunction["assembly-ast"]["nodes"].extend(astree.serialize_symboltable())
                astfunction["assembly-ast"]["startnode"] = ast.id
                astfunction["lifted-ast"] = {}
                astfunction["lifted-ast"]["nodes"] = astreduced.serialize()
                astfunction["lifted-ast"]["nodes"].extend(astree.serialize_symboltable())
                astfunction["lifted-ast"]["startnode"] = astreduced.id
                astfunction["spans"] = astree.spans
                astfunction["available-expressions"] = availablexprs
                astfunction["storage"] = storagerecords
                astfunctions.append(astfunction)

                jsonfilenames[fname] = xfile + "_" + faddr + "_ast.json"
                with open(jsonfilenames[fname], "w") as fp:
                    json.dump(ast_output, fp, indent=2)

                if args.verbose or len(available_exprs) > 0:
                    dastree = D.AbstractSyntaxTree(
                        astfunction["lifted-ast"]["nodes"],
                        astfunction["lifted-ast"]["startnode"],
                        astfunction["available-expressions"],
                        astfunction["spans"])
                    print("\nDeserialized lifted ast")
                    print(str(dastree.to_c_like()))

                    if len(available_exprs) > 0:
                        print("\nAvailable expressions for " + ", ".join(available_exprs))
                        print(dastree.var_available_expressions(available_exprs))

                    if len(astree.notes) > 0:
                        print("\nNotes")
                        print("=" * 80)
                        print("\n".join(astree.notes))
                        print("=" * 80)

        else:
            print_error("Function " + faddr + " not found")
            exit(1)

    if decompile:
        print("\nStatistics:")
        print("Functions decompiled : " + str(functioncount))
        print("Functions that failed: " + str(failedfunctions))
        print("Functions excluded   : " + str(excluded))
        if len(opc_unsupported) > 0:
            print("Unsupported opcodes: ")
            for (opc, count) in sorted(opc_unsupported.items()):
                print("  " + opc.ljust(10) + str(count).rjust(5))
    else:
        print("\nAST(s) were saved in:")
        for (fname, ffile) in jsonfilenames.items():
            ffile = os.path.abspath(ffile)
            print("  " + fname + ": " + ffile)
        print("-" * 80)

    exit(0)


def extract_edges(edges: List[str]) -> List[Tuple[str, str]]:
    result: List[Tuple[str, str]] = []
    for x in edges:
        if ":" in x:
            edge = x.split(":")
            if len(edge) == 2:
                result.append((edge[0], edge[1]))
            else:
                print_error(
                    "Error in format of edge specification: "
                    + x
                    + "; Edge has " + str(len(edge)) + " components: "
                    + ", ".join(edge))
                exit(1)
        else:
            print_error(
                "Error in format of edge specification: "
                + x
                + "; Expected to find colon separator")
            exit(1)
    return result


def showcfg(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    faddr: str = args.faddr
    out: str = args.out
    xview: bool = args.view
    xpredicates: bool = args.predicates
    xcalls: bool = args.calls
    xstores: bool = args.stores
    xinstr_opcodes: bool = args.instr_opcodes
    xinstr_text: bool = args.instr_text
    xsink: Optional[str] = args.sink
    xsegments: List[str] = args.segments
    xsave_edges: bool = args.save_edges
    xderivedgraph: bool = args.derivedgraph
    remove_edges: List[str] = args.remove_edges
    add_edges: List[str] = args.add_edges

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
        if len(remove_edges) + len(add_edges) > 0:
            rmedges = extract_edges(remove_edges)
            adedges = extract_edges(add_edges)
            f.cfg.modify_edges(rmedges, adedges)

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
            showstores=xstores,
            mips=xinfo.is_mips,
            sink=xsink,
            segments=xsegments)

        fname = faddr
        if app.has_function_name(faddr):
            fname = fname + " (" + app.function_name(faddr) + ")"

        pdffilename = UD.print_dot(app.path, out, dotcfg.build())

        if xderivedgraph:
            graphseq = f.cfg.derived_graph_sequence
            graphseq.to_dot(app.path, xfile + "_graphseq_" + faddr)

        if xsave_edges:
            edges = f.cfg.edges
            jsonfile = os.path.join(app.path, out) + ".json"
            with open(jsonfile, "w") as fp:
                json.dump(edges, fp, indent=2)

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
            blocksinks = {i.block.baddr: i for i in instrs}
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
                pathconstraints0 = [
                    str(c) for c in paths[sink][0].constraints() if c]
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
