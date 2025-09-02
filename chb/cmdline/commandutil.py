#!/usr/bin/env python3
# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2025  Aarno Labs, LLC
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

import logging

import argparse
from chb.elfformat.ELFHeader import ELFHeader
from chb.peformat.PEHeader import PEHeader
import datetime
import json
import os
import shutil
import subprocess
import sys

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

from chb.app.AppAccess import AppAccess
from chb.app.Assembly import Assembly

from chb.app.Callgraph import CallgraphNode

from chb.arm.ARMAccess import ARMAccess
from chb.arm.ARMAssembly import ARMAssembly

from chb.bctypes.BCFiles import BCFiles

from chb.cmdline.AnalysisManager import AnalysisManager

from chb.invariants.InputConstraint import InputConstraint
from chb.invariants.XXpr import XXpr
from chb.invariants.XVariable import XVariable

from chb.jsoninterface.JSONSchemaRegistry import json_schema_registry

from chb.mips.MIPSAccess import MIPSAccess
from chb.mips.MIPSAssembly import MIPSAssembly
from chb.mips.MIPSCfgPath import MIPSCfgPath
from chb.mips.MIPSFunction import MIPSFunction
from chb.mips.MIPSInstruction import MIPSInstruction

from chb.pwr.PowerAccess import PowerAccess

import chb.cmdline.jsonresultutil as JU
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
from chb.util.loggingutil import chklogger, LogLevel
import chb.util.xmlutil as UX

from chb.app.Instruction import Instruction

from chb.x86.X86Access import X86Access

if TYPE_CHECKING:
    import chb.app.Instruction
    import chb.arm.ARMInstruction
    from chb.bctypes.BCCompInfo import BCCompInfo
    from chb.bctypes.BCTyp import BCTypComp, BCTypFun, BCTypNamed, BCTypPtr
    from chb.invariants.InvariantFact import RelationalFact
    import chb.mips.MIPSInstruction
    import chb.x86.X86Instruction


def print_error(m: str) -> None:
    sys.stderr.write(("*" * 80) + "\n")
    sys.stderr.write(m + "\n")
    sys.stderr.write(("*" * 80) + "\n")


def print_status_update(m: str) -> None:
    sys.stderr.write("[chkx] " + m + "\n")


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


def set_logging(
        level: str,
        path: str,
        logfilename: Optional[str],
        msg: str = "",
        mode: str = "a") -> None:

    if level in LogLevel.all() or logfilename is not None:
        if logfilename is not None:
            logfilename = os.path.join(path, logfilename)

        chklogger.set_chkx_logger(
            msg, level=level, logfilename=logfilename, mode=mode)


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
    elif arch == "power":
        return PowerAccess(path, xfile, fileformat=format)
    else:
        return PowerAccess(path, xfile, fileformat=format)
        # raise UF.CHBError("Archicture " + arch + " not yet supported")


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
        md5: str) -> UserHints:
    """Convert hints and command-line options to xml user data."""

    userhints = UserHints()

    # check for registered userdata
    if UF.file_has_registered_userdata(md5):
        print_status_update("Use registered userdata.")
        userdata = UF.get_file_registered_userdata(md5)
        userhints.add_hints(userdata)

    # check for registered options
    if UF.file_has_registered_options(md5):
        cmdline_options = UF.get_file_registered_options(md5)
        if "thumb" in cmdline_options["options"]:
            thumb = cmdline_options["options"]["thumb"]
            print_status_update("Use command-line options for " + cmdline_options["name"] + ": ")
            print_status_update(" --thumb " + " ".join(thumb))
            armuserdata: Dict[str, List[str]] = {}
            armuserdata["arm-thumb"] = thumb
            userhints.add_hints(armuserdata)

    # check direct command-line options
    if len(thumb) > 0:
        print_status_update("Use command-line options for thumb: ")
        print_status_update(" --thumb " + " ".join(thumb))
        cmdarmuserdata: Dict[str, List[str]] = {}
        cmdarmuserdata["arm-thumb"] = thumb
        userhints.add_hints(cmdarmuserdata)

    # read hints files
    # os.chdir(path)
    filenames = [os.path.abspath(s) for s in hints]
    if len(filenames) > 0:
        print_status_update("Use hints files: " + ", ".join(filenames))
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
    return userhints


def prepare_executable(
        path: str,
        xfile: str,
        doreset: bool,
        doresetx: bool,
        verbose: bool = False,
        exclude_debug: bool = False,
        hints: List[str] = [],
        thumb: List[str] = []) -> UserHints:
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
                print_status_update("Remove " + xtargz)
                os.remove(xtargz)
                shutil.rmtree(chdir)

        else:
            pass

    if os.path.isfile(xtargz):
        chdir = UF.get_ch_dir(path, xfile)
        if os.path.isdir(chdir) and not (doreset or doresetx):
            # everything is in place
            return UserHints()     # TODO: to be changed

        if os.path.isdir(chdir) and (doreset or doresetx):
            # remove existing x.ch directory
            print_status_update("Removing " + chdir)
            shutil.rmtree(chdir)

        # unpack existing targz file
        if UF.unpack_tar_file(path, xfile):
            print_status_update(
                "Successfully extracted "
                + UF.get_executable_targz_filename(path, xfile))
        else:
            raise UF.CHBError("Error in unpacking tar.gz file")

        # set up user data from hints files
        xinfo = XI.XInfo()
        xinfo.load(path, xfile)
        setup_directories(path, xfile)
        userhints = setup_user_data(path, xfile, hints, thumb, xinfo.md5)
        return userhints

    # executable content has to be extracted
    else:
        xinfo = create_xinfo(path, xfile)

        # check architecture and file format
        if not (xinfo.is_x86
                or xinfo.is_power
                or xinfo.is_mips
                or xinfo.is_arm):
            print("Architecture "
                              + xinfo.architecture
                              + " not supported")
        if not (xinfo.is_pe32 or xinfo.is_elf):
            raise UF.CHBError("File format "
                              + xinfo.format
                              + " not supported")

        # set up directories and user data
        setup_directories(path, xfile)
        userhints = setup_user_data(path, xfile, hints, thumb, xinfo.md5)
        xinfo.save(path, xfile)

        # extract executable content
        am = AnalysisManager(
            path,
            xfile,
            xinfo.size,
            mips=xinfo.is_mips,
            arm=xinfo.is_arm,
            power=xinfo.is_power,
            elf=xinfo.is_elf,
            exclude_debug=exclude_debug)

        print_status_update("Extracting executable content into xml ...")
        result = am.extract_executable(
            chcmd="-extract", verbose=verbose)
        if not (result == 0):
            raise UF.CHBError("Error in extracting executable")

        # save the targz file
        am.save_extract()
        return userhints


def analyzecmd(args: argparse.Namespace) -> NoReturn:
    """Invoke analyzer to extract, or disassemble, do full analysis."""

    # arguments
    xname: str = args.xname
    doreset: bool = args.reset
    doresetx: bool = args.resetx
    exclude_debug: bool = args.exclude_debug
    dodisassemble: bool = args.disassemble
    savedatablocks: str = args.save_datablocks
    outputfile: str = args.outputfile
    doextract: bool = args.extract
    verbose: bool = args.verbose
    collectdiagnostics: bool = args.collect_diagnostics
    failonfunctionfailure: bool = args.fail_on_function_failure
    save_asm: bool = args.save_asm
    save_asm_cfg_info: bool = args.save_asm_cfg_info
    print_datasections: List[str] = args.print_datasections
    thumb: List[str] = args.thumb
    preamble_cutoff: int = args.preamble_cutoff
    iterations: int = args.iterations
    analysisrepeats: int = args.analysisrepeats
    deps: List[str] = args.thirdpartysummaries
    so_libraries: List[str] = args.so_libraries
    skip_if_asm: bool = args.skip_if_asm
    skip_if_metrics: bool = args.skip_if_metrics
    hints: List[str] = args.hints  # names of json files
    headers: List[str] = args.headers   # names of c files
    fns_no_lineq: List[str] = args.fns_no_lineq  # function hex addresses
    fns_exclude: List[str] = args.fns_exclude  # function hex addresses
    fns_include: List[str] = args.fns_include  # function hex addresses
    analyze_all_named: bool = args.analyze_all_named
    analyze_range_entry_points: List[str] = args.analyze_range_entry_points
    gc_compact: int = args.gc_compact
    construct_all_functions: bool = args.construct_all_functions
    show_function_timing: bool = args.show_function_timing
    lineq_instr_cutoff: int = args.lineq_instr_cutoff
    lineq_block_cutoff: int = args.lineq_block_cutoff
    xssa: bool = args.ssa    # use ssa in analysis
    xnovarinvs: bool = args.no_varinvs  # don't generate var invariants
    xarmextensionregisters: bool = args.arm_extension_registers
    loglevel: str = args.loglevel
    logfilename: Optional[str] = args.logfilename
    logfilemode: str = args.logfilemode

    failonfunctionfailure = failonfunctionfailure or len(fns_include) == 1

    if not os.path.isfile(Config().chx86_analyze):
        print_error(
            "CodeHawk analyzer executable not found.\n"
            + ("~" * 80) + "\n"
            + "Copy CHB/bchcmdline/chx86_analyze from the (compiled) "
            + "codehawk repository to the\nchb/bin/binaries/linux directory "
            + "in this directory, or\n"
            + "set up ConfigLocal.py with another location for chx86_analyze")
        exit(1)

    try:
        (path, xfile) = get_path_filename(xname)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    set_logging(
        loglevel,
        path,
        logfilename=logfilename,
        mode=logfilemode,
        msg="analyze invoked")

    if skip_if_asm and UF.has_asm_results(path, xfile):
        # we have what we need
        print_status_update("Skip disassembly of " + xname)
        exit(0)

    if skip_if_metrics and UF.has_analysis_results(path, xfile):
        # we have what we need
        print_status_update("Skip analysis of " + xname)
        exit(0)

    try:
        userhints = prepare_executable(
            path,
            xfile,
            doreset,
            doresetx,
            verbose=verbose,
            hints=hints,
            exclude_debug=exclude_debug,
            thumb=thumb)
    except UF.CHBError as e:
        print_error(str(e.wrap()))
        exit(1)

    if doextract:
        # we are done
        chklogger.logger.info("analyze -x completed")
        exit(0)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    # preprocess c files
    print_status_update(
        "Preprocessing c header files from directory " + os.getcwd())
    ifilenames: List[str] = []
    headerfilenames = [os.path.abspath(s) for s in headers]
    if len(headers) > 0:
        for f in headerfilenames:
            if os.path.isfile(f):
                print_status_update("Use header file: " + f)
                ifilename = f[:-2] + ".i"
                ifilenames.append(ifilename)
                gcccmd = ["gcc", "-std=gnu99", "-m32", "-E", "-o", ifilename, f]
                p = subprocess.call(gcccmd, cwd=path, stderr=subprocess.STDOUT)
                if not (p == 0):
                    print_error("Error in " + str(gcccmd))
                    exit(1)
            else:
                print_error("Header file " + f + " not found")
                exit(1)

    if analyze_all_named:
        fnnamed_addrs = userhints.rev_function_names().values()
        fns_include = fns_include + list(fnnamed_addrs)
        chklogger.logger.info("Include %d functions", len(fns_include))

    if len(analyze_range_entry_points) == 2:
        festart = int(analyze_range_entry_points[0], 16)
        fefin = int(analyze_range_entry_points[1], 16)
        fentrypoints = userhints.function_entry_points()
        feincludes: List[str] = []
        for fe in fentrypoints:
            eint = int(fe, 16)
            if eint >= festart and eint <= fefin:
                feincludes.append(fe)
        fns_include = fns_include + feincludes
        chklogger.logger.info(
            "Include %d entry point functions in range %s - %s",
            len(feincludes), hex(festart), hex(fefin))

    am = AnalysisManager(
        path,
        xfile,
        xinfo.size,
        mips=xinfo.is_mips,
        arm=xinfo.is_arm,
        power=xinfo.is_power,
        elf=xinfo.is_elf,
        savedatablocks=(savedatablocks is not None),
        deps=deps,
        so_libraries=so_libraries,
        ifilenames=ifilenames,
        fns_no_lineq=fns_no_lineq,
        fns_exclude=fns_exclude,
        fns_include=fns_include,
        gc_compact=gc_compact,
        show_function_timing=show_function_timing,
        lineq_instr_cutoff=lineq_instr_cutoff,
        lineq_block_cutoff=lineq_block_cutoff,
        use_ssa=xssa,
        no_varinvs=xnovarinvs,
        include_arm_extension_registers=xarmextensionregisters,
        thumb=(len(thumb) > 0))

    if dodisassemble:
        try:
            am.disassemble(
                verbose=verbose,
                collectdiagnostics=collectdiagnostics,
                preamble_cutoff=preamble_cutoff,
                save_asm_cfg_info=save_asm_cfg_info,
                print_datasections=print_datasections)
        except subprocess.CalledProcessError as e:
            print_error(str(e.output))
            print_error(str(e))
            exit(1)
        except UF.CHBError as e:
            print_error(str(e.wrap()))
            exit(1)

        if savedatablocks is not None and outputfile is not None:
            (startaddr, endaddr) = savedatablocks.split(":")
            app = get_app(path, xfile, xinfo)
            systeminfo = app.systeminfo
            datablocks = systeminfo.datablocks.datablocks_in_range(
                startaddr, endaddr)
            userdata: Dict[str, Any] = {}
            udata = userdata["userdata"] = {}
            dbdata = udata["data-blocks"] = []
            for db in datablocks:
                dbrec: Dict = {}
                dbrec["r"] = [db.startaddr, db.endaddr]
                dbdata.append(dbrec)
            with open(outputfile + ".json", "w") as fp:
                json.dump(userdata, fp, indent=2)

        chklogger.logger.info("analyze -d completed")
        exit(0)

    else:
        try:
            am.analyze(
                analysisrepeats=analysisrepeats,
                iterations=iterations,
                verbose=verbose,
                save_asm=save_asm,
                construct_all_functions=construct_all_functions,
                collectdiagnostics=collectdiagnostics,
                failonfunctionfailure=failonfunctionfailure,
                preamble_cutoff=preamble_cutoff)
        except subprocess.CalledProcessError as e:
            print_error(
                "Analysis failed.\n  Return code: "
                + str(e.returncode)
                + "\n  Command: "
                + str(e.cmd)
                + "\n  Output: "
                + str(e.output)
                + "\n  Stderr: "
                + str(e.stderr)
                + "\n"
                + ("-" * 80)
                + "\n"
                + str(e))
            exit(1)
        except UF.CHBError as e:
            print_error(str(e.wrap()))
            exit(1)

        chklogger.logger.info("analyze completed")
        exit(0)


def results_stats(args: argparse.Namespace) -> NoReturn:
    """Prints out a summary of the analysis results per function."""

    # arguments
    xname: str = str(args.xname)
    nocallees: bool = args.nocallees
    sortby: str = args.sortby
    timeshare: int = args.timeshare
    opcodes: str = args.opcodes
    functionmetrics: str = args.functionmetrics
    hide: List[str] = args.hide
    tagfile: Optional[str] = args.tagfile
    loglevel: str = args.loglevel
    logfilename: Optional[str] = args.logfilename
    logfilemode: str = args.logfilemode

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print_error(str(e.wrap()))
        exit(1)

    set_logging(
        loglevel,
        path,
        logfilename=logfilename,
        mode=logfilemode,
        msg="results stats invoked")

    tagdata: Dict[str, Any] = {}
    if tagfile is not None:
        with open(tagfile, "r") as fp:
            tagdata = json.load(fp)

    functiontags: Dict[str, List[str]] = {}

    if "function-tags" in tagdata:
        functiontags = tagdata["function-tags"]

    maxlen = 0
    for (faddr, keys) in functiontags.items():
        taglen = len(",".join(keys))
        if taglen > maxlen:
            maxlen = taglen
    maxlen = maxlen + 4 if maxlen > 0 else 0

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    stats = app.result_metrics
    print(stats.header_to_string(hide=hide))
    if sortby == "instrs":
        sortkey = lambda f: f.instruction_count
    elif sortby == "basicblocks":
        sortkey = lambda f: (f.block_count, f.instruction_count, int(f.faddr, 16))
    elif sortby == "loopdepth":
        sortkey = lambda f: f.loop_depth
    elif sortby == "time":
        sortkey = lambda f: f.time
    else:
        sortkey = lambda f: int(f.faddr, 16)
    for f in sorted(stats.get_function_results(), key=sortkey):
        if f.faddr in functiontags:
            fn_tags = functiontags[f.faddr]
        else:
            fn_tags = []
        if "hide" in fn_tags:
            continue
        print(f.metrics_to_string(shownocallees=nocallees, hide=hide,
                                  tags=fn_tags, taglen=maxlen))

    print(stats.disassembly_to_string())
    print(stats.analysis_to_string())
    if timeshare > 0:
        topanalysistimes = stats.time_share(timeshare)
        toptotal = sum(topanalysistimes.values())
        print("\nFunctions taking up most analysis time:")
        print("\nAddress     share (%)")
        print("-----------------------")
        for (s, t) in topanalysistimes.items():
            print(s.ljust(14) + "{:4.2f}".format(100.0 * t).rjust(6))
        print("-----------------------")
        print("Total".ljust(14) + "{:4.2f}".format(100.0 * toptotal).rjust(6))

    if functionmetrics:
        filename = functionmetrics + ".json"
        content: Dict[str, Any] = {}
        content["filename"] = xname
        content["functions"] = []
        for f in sorted(stats.get_function_results(), key=lambda f: f.faddr):
            content["functions"].append(f.to_json_result().content)
        jsonok = JU.jsonok("functionmetrics", content)
        with open(filename, "w") as fp:
            json.dump(jsonok, fp, indent=4)

    if opcodes:
        filename = opcodes + ".json"
        opcstats = app.mnemonic_stats()
        if xinfo.is_arm:
            opccovered = Config().armopcodes
            with open(opccovered, "r") as fp:
                opcsupport: Dict[str, Any] = json.load(fp)["instructions"]
        else:
            opcsupport = {}
        result: Dict[str, Any] = {}
        result["name"] = xname
        result["md5"] = xinfo.md5
        result["opcodes"] = {}
        for (opc, count) in sorted(opcstats.items()):
            opcrec: Dict[str, Any] = {}
            opcrec["count"] = count
            opcrec["support"] = []
            if opc in opcsupport:
                if "ASTC" in opcsupport[opc]:
                    if opcsupport[opc]["ASTC"] == "Y":
                        opcrec["support"].append("ASTC")
            result["opcodes"][opc] = opcrec
        with open(filename, "w") as fp:
            json.dump(result, fp, sort_keys=True, indent=2)
        chklogger.logger.info("opcodes saved to " + filename)
        print("\nOpcode stats")
        print("-" * 80)
        for (opc, opcr) in sorted(result["opcodes"].items()):
            p_opcsupport = ""
            if len(opcr["support"]) > 0:
                p_opcsupport = "(" + ", ".join(opcr["support"]) + ")"
            print(opc.ljust(10) + ": "
                  + str(opcr["count"]).rjust(6)
                  + " " + p_opcsupport)
        print("=" * 80)
    chklogger.logger.info("results stats completed")

    exit(0)


def results_callgraph(args: argparse.Namespace) -> NoReturn:
    """Generates a callgraph in dot."""

    # arguments
    xname: str = args.xname
    output: str = args.output
    hidelibs: bool = args.hide_lib_functions
    hideunknowns: bool = args.hide_unknown_targets
    reverse: bool = args.reverse
    align: str = args.align
    sources: List[str] = args.sources
    sinks: List[str] = args.sinks
    loglevel: str = args.loglevel
    logfilename: Optional[str] = args.logfilename
    logfilemode: str = args.logfilemode

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    set_logging(
        loglevel,
        path,
        logfilename=logfilename,
        mode=logfilemode,
        msg="results callgraph invoked")

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
    pdffilename = UD.print_dot(app.path, output, dotgraph)

    if os.path.isfile(pdffilename):
        print_info(
            "Call graph for " + xname + " has been saved in " + pdffilename)

    else:
        print_error(
            "Error in converting dot file to pdf: file "
            + pdffilename
            + " not found")
        exit(1)

    chklogger.logger.info("results callgraph completed")

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

    total_lhs_assignments = 0
    for faddr in lhsglobals:
        total_lhs_assignments += len(lhsglobals[faddr])

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

    print("\nGlobal expressions (" + str(len(rhsdir)) + ")")
    print("---------------------------------------")
    for gx in sorted(rhsdir):
        print("\nGlobal expression " + gx)
        for faddr in sorted(rhsdir[gx]):
            print("  " + faddr + ": " + str(rhsdir[gx][faddr]))

    print("\nGlobal variable statistics")
    print("---------------------------------------")
    print("Number of functions in which globals get assigned: "
          + str(len(lhsglobals)))
    print("Total number of global variable assignments: "
          + str(total_lhs_assignments))
    print("Total number of functions in which globals get referenced: "
          + str(len(rhsglobals)))

    exit(0)


def results_classifyfunctions(args: argparse.Namespace) -> NoReturn:
    """Returns a classification of function based on a classifier."""

    xname: str = str(args.xname)
    classificationfile: str = str(args.classification_file)

    with open(classificationfile, "r") as fp:
        classifier = json.load(fp)

    revclassifier: Dict[str, str] = {}
    for category in classifier["classification"]:
        for libfun in classifier["classification"][category]:
            revclassifier[libfun] = category

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)
    fns = app.appfunction_addrs

    classification: Dict[str, Dict[str, int]] = {}  # faddr -> libcat -> count

    for faddr in fns:
        classification.setdefault(faddr, {})
        f = app.function(faddr)
        fcalls = f.call_instructions()
        for baddr in fcalls:
            for instr in fcalls[baddr]:
                tgtname = instr.call_target.name
                if tgtname in revclassifier:
                    category = revclassifier[tgtname]
                    classification[faddr].setdefault(category, 0)
                    classification[faddr][category] += 1

    catfprevalence: Dict[str, int] = {}
    catcprevalence: Dict[str, int] = {}
    catstats: Dict[int, int] = {}
    singlecat: Dict[str, int] = {}
    doublecat: Dict[Tuple[str, str], int] = {}
    for faddr in classification:
        for cat in classification[faddr]:
            catfprevalence.setdefault(cat, 0)
            catcprevalence.setdefault(cat, 0)
            catfprevalence[cat] += 1
            catcprevalence[cat] += classification[faddr][cat]

        numcats = len(classification[faddr])
        catstats.setdefault(numcats, 0)
        catstats[numcats] += 1
        if numcats == 1:
            cat = list(classification[faddr].keys())[0]
            singlecat.setdefault(cat, 0)
            singlecat[cat] += 1

        if numcats == 2:
            cats = sorted(list(classification[faddr].keys()))
            cattuple = (cats[0], cats[1])
            doublecat.setdefault(cattuple, 0)
            doublecat[cattuple] += 1

    for (m, c) in sorted(catstats.items()):
        print(str(m).rjust(5) + ": " + str(c).rjust(5))

    print("\nSingle category")
    for (cat, count) in sorted(singlecat.items()):
        print(str(count).rjust(5) + "  " + cat)

    print("\nDouble category")
    for ((cat1, cat2), count) in sorted(doublecat.items()):
        print(str(count).rjust(5) + "  " + cat1 + ", " + cat2)

    classificationresults: Dict[str, Any] = {}
    classificationresults["catfprevalence"] = catfprevalence
    classificationresults["catcprevalence"] = catcprevalence
    classificationresults["functions"] = classification

    with open("classification_results.json", "w") as fp:
        json.dump(classificationresults, fp, indent=2)

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
    stacklayout: bool = args.stacklayout
    proofobligations: bool = args.proofobligations
    loglevel: str = args.loglevel
    logfilename: Optional[str] = args.logfilename
    logfilemode: str = args.logfilemode

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    set_logging(
        loglevel,
        path,
        logfilename=logfilename,
        mode=logfilemode,
        msg="results functions invoked")

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)
    if len(functions) == 0:
        fns: Sequence[str] = sorted(app.appfunction_addrs, key=lambda f:int(f, 16))
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
                print(str(f.finfo.appsummary))
                print("-" * 80)
                print(f.to_string(
                    bytestring=bytestring,
                    bytes=bytes,
                    hash=hash,
                    sp=True,
                    opcodetxt=True,
                    opcodewidth=opcodewidth,
                    proofobligations=proofobligations,
                    stacklayout=stacklayout))

            except UF.CHBError as e:
                print(str(e.wrap()))

        else:
            print_error("Function " + faddr + " not found")
            continue

    chklogger.logger.info("results functions completed")

    exit(0)


def results_function(args: argparse.Namespace) -> NoReturn:
    """Prints out annotated assembly listing of a function."""

    # arguments
    xname: str = str(args.xname)
    xfaddr: str = args.faddr
    xjson: bool = args.json
    xoutput: str = args.output
    hash: bool = args.md5hash
    bytestring: bool = args.bytestring
    bytes: bool = args.bytes
    opcodewidth: int = args.opcodewidth
    txtoutput: bool = not xjson
    stacklayout: bool = args.stacklayout
    proofobligations: bool = args.proofobligations
    typingrules: bool = args.typingrules
    loglevel: str = args.loglevel
    logfilename: Optional[str] = args.logfilename
    logfilemode: str = args.logfilemode

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print_error(str(e.wrap()))
        exit(1)

    set_logging(
        loglevel,
        path,
        logfilename=logfilename,
        mode=logfilemode,
        msg="results function invoked")

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    if not app.has_function(xfaddr):
        msg = "Function " + xfaddr + " not found"
        chklogger.logger.error(msg)
        if xjson:
            jsonfresult = JU.jsonfail(msg)
            if xoutput is not None:
                with open(xoutput, "w") as fp:
                    json.dump(jsonfresult, fp)
                chklogger.logger.error(
                    "json file saved in " + xoutput + " (failure)")
            else:
                print(json.dumps(jsonfresult))

        print_error(msg)
        exit(1)

    f = app.function(xfaddr)
    if txtoutput:
        lines: List[str] = []
        try:
            if app.has_function_name(xfaddr):
                lines.append(
                    "\nFunction "
                    + xfaddr
                    + " ("
                    + app.function_name(xfaddr)
                    + ")")
            else:
                lines.append("\nFunction " + xfaddr)
            lines.append("-" * 80)
            lines.append(str(f.finfo.appsummary))
            lines.append("-" * 80)
            lines.append(f.to_string(
                bytestring=bytestring,
                bytes=bytes,
                hash=hash,
                sp=True,
                opcodetxt=True,
                proofobligations=proofobligations,
                typingrules=typingrules,
                stacklayout=stacklayout,
                opcodewidth=opcodewidth))
        except UF.CHBError as e:
            print_error(str(e.wrap()))
            exit(1)

        if xoutput:
            with open(xoutput, "w") as fp:
                fp.write("\n".join(lines))
                chklogger.logger.info("Text output written to " + xoutput)
        else:
            print("\n".join(lines))
        exit(0)

    else:
        fresult = f.to_json_result()
        if fresult.is_ok:
            jsonokresult = JU.jsonok("assemblyfunction", fresult.content)
            if xoutput:
                with open(xoutput, "w") as fp:
                    json.dump(jsonokresult, fp)
                chklogger.logger.info("JSON output written to " + xoutput)
            else:
                print(json.dumps(jsonokresult))
            exit(0)

        else:
            jsonfresult = JU.jsonfail(fresult.reason)
            if xoutput:
                with open(xoutput, "w") as fp:
                    json.dump(jsonfresult, fp)
                chklogger.logger.error(
                    "JSON (failure) output written to " + xoutput)
            else:
                print(json.dumps(jsonfresult))
            exit(1)


def results_callbacktables(args: argparse.Namespace) -> NoReturn:
    """Prints or saves information regarding callback tables."""

    # arguments
    xname: str = str(args.xname)
    xshowall: bool = args.showall
    xlist: bool = args.list
    xoutput: Optional[str] = args.output
    xdevice: Optional[str] = args.device

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)
    app = get_app(path, xfile, xinfo)

    if xshowall:
        for (addr, cbtable) in app.callbacktables.callbacktables.items():
            print("\nAddress: " + addr + " (" + str(len(cbtable.records)) + " records)")
            print(str(cbtable))

    elif xlist:
        for (addr, cbtable) in app.callbacktables.callbacktables.items():
            print("\nAddress  : " + addr)
            print("Size     : " + str(len(cbtable.records)) + " records")
            print("Structure:")
            for (offset, tag) in sorted(cbtable.structure.items()):
                print(str(offset).rjust(4) + "  " + tag)

    if xoutput is not None:
        filename = xoutput + ".json"
        cbdata: Dict[str, Any] = {}
        cbdata["name"] = xfile
        if xdevice is not None:
            cbdata["device"] = xdevice
        cbdata["tables"] = {}
        for (addr, cbtable) in app.callbacktables.callbacktables.items():
            cbdata["tables"][addr] = {}
            cbdata["tables"][addr]["structure"] = cbtable.structure
            cbdata["tables"][addr]["records"] = cbtable.serialize()
        with open(filename, "w") as fp:
            json.dump(cbdata, fp, indent=2)

    exit(0)


def results_finfo(args: argparse.Namespace) -> NoReturn:
    """Prints out information collected about a function during analysis."""

    # arguments
    xname: str = str(args.xname)
    xfaddr: str = args.faddr

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    if not app.has_function(xfaddr):
        msg = "Function " + xfaddr + " not found"
        print_error(msg)
        exit(1)

    f = app.function(xfaddr)

    print("Summary:")
    print(str(f.finfo.appsummary))

    calltargetinfos = f.finfo.calltargetinfos
    for instrs in f.call_instructions().values():
        for instr in instrs:
            print("\n")
            ctinfo = calltargetinfos[instr.iaddr]
            print(str(instr))
            print(str(ctinfo))

    exit(0)


def results_globalrefs(args: argparse.Namespace) -> NoReturn:
    """Prints out a list of global references made within a function."""

    # arguments
    xname: str = str(args.xname)
    xfaddr: str = args.faddr

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    if not app.has_function(xfaddr):
        print_error("Function " + xfaddr + " not found")
        exit(1)

    f = app.function(xfaddr)
    for (gaddr, grefs) in f.globalrefs().items():
        print(gaddr)
        for gref in grefs:
            print(str("  " + str(gref)))

    exit(0)


def results_invariants(args: argparse.Namespace) -> NoReturn:
    """Prints out a list of invariants for a function per location."""

    # arguments
    xname: str = str(args.xname)
    xfaddr: str = args.faddr
    xjson: bool = args.json
    xoutput: str = args.output
    xinclude: List[str] = args.include
    xexclude: List[str] = args.exclude
    txtoutput: bool = not xjson

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

    if not app.has_function(xfaddr):
        msg = "Function " + xfaddr + " not found"
        if xjson:
            jsonfresult = JU.jsonfail(msg)
            if xoutput is not None:
                with open(xoutput, "w") as fp:
                    json.dump(jsonfresult, fp)
            else:
                print(json.dumps(jsonfresult))

        print_error(msg)
        exit(1)

    f = app.function(xfaddr)
    if txtoutput:
        lines: List[str] = []

        try:
            invariants = f.invariants
            for loc in sorted(invariants):
                if any(f.is_unreachable for f in invariants[loc]):
                    lines.append(loc + ": unreachable")
                else:
                    lines.append(loc)
                    for fact in invariants[loc]:
                        if (
                                fact.is_initial_var_disequality
                                or fact.is_initial_var_equality):
                            continue
                        pfact = str(fact)
                        if fact.is_relational:
                            fact = cast("RelationalFact", fact)
                            equality = fact.equality.simple_equality
                            if equality is not None:
                                pfact = f"{equality[0]} == {equality[1]} (eq)"

                        if len(xinclude) == 0:
                            if in_exclude(pfact):
                                continue
                            else:
                                lines.append("  " + pfact)
                        else:
                            if (in_include(pfact) and not in_exclude(pfact)):
                                lines.append("  " + pfact)
        except UF.CHBError as e:
            print_error(str(e.wrap()))
            exit(1)

        if xoutput:
            with open(xoutput, "w") as fp:
                fp.write("\n".join(lines))
        else:
            print("\n".join(lines))
        exit(0)

    else:
        fresult = JU.function_invariants_to_json_result(f.invariants)
        if fresult.is_ok:
            # fschema = json_schema_registry.get_definition("functioninvariants")
            jsonokresult = JU.jsonok("functioninvariants", fresult.content)
            if xoutput:
                with open(xoutput, "w") as fp:
                    json.dump(jsonokresult, fp)
            else:
                print(json.dumps(jsonokresult))
            exit(0)

        else:
            jsonfresult = JU.jsonfail(fresult.reason)
            if xoutput:
                with open(xoutput, "w") as fp:
                    json.dump(jsonfresult, fp)
            else:
                print(json.dumps(jsonfresult))
            exit(1)


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


def results_structs(args: argparse.Namespace) -> NoReturn:
    """Return a json file with struct variables / expressions."""

    # arguments
    xname: str = str(args.xname)

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print_error(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    lhsvars = app.get_lhs_variables(lambda v: v.is_structured_var)
    rhsxprs = app.get_rhs_expressions(
        lambda x: x.is_structured_expr and not x.is_compound)

    results: Dict[str, Dict[str, Dict[str, int]]] = {}

    # statistics
    lhsfreq: Dict[str, int] = {}
    rhsfreq: Dict[str, int] = {}

    for (faddr, fvars) in lhsvars.items():
        results.setdefault(faddr, {})
        for v in fvars:
            strv = str(v)
            results[faddr].setdefault("vars", {})
            results[faddr]["vars"].setdefault(strv, 0)
            results[faddr]["vars"][strv] += 1
            lhsfreq.setdefault(strv, 0)
            lhsfreq[strv] += 1

    for (faddr, xprs) in rhsxprs.items():
        results.setdefault(faddr, {})
        for x in xprs:
            strx = str(x)
            results[faddr].setdefault("xprs", {})
            results[faddr]["xprs"].setdefault(strx, 0)
            results[faddr]["xprs"][strx] += 1
            if strx.endswith("_in"):
                strx = strx[:-3]
            rhsfreq.setdefault(strx, 0)
            rhsfreq[strx] += 1

    print("Structs")
    for (faddr, d) in sorted(results.items()):
        if app.has_function_name(faddr):
            print(
                "\n\nFunction "
                + faddr
                + " ("
                + app.function_name(faddr)
                + ")")
        else:
            print("\n\nFunction " + faddr)

        if "vars" in d:
            print("  Lhs variables")
            for (vs, c) in sorted(d["vars"].items()):
                print(str(c).rjust(8) + " " + str(vs))
        if "xprs" in d:
            print("  Rhs expressions")
            for (xs, c) in sorted(d["xprs"].items()):
                print(str(c).rjust(8) + " " + str(xs))

    print("\n\nStatistics")
    print("Functions with structs: " + str(len(results)))
    print("Distinct lhs          : " + str(len(lhsfreq)))
    print("Distinct rhs          : " + str(len(rhsfreq)))
    print("Total number of lhs   : " + str(sum(lhsfreq[s] for s in lhsfreq)))
    print("Total number of rhs   : " + str(sum(rhsfreq[s] for s in rhsfreq)))
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
    callbacktable: bool = args.callbacktable
    callbacktables: bool = args.callbacktables
    showtags: bool = args.showtags

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

    elif callbacktable:
        if addr in app.callbacktables.callbacktables:
            cbtable = app.callbacktables.callbacktable(addr)
            outfilename = xout + ".json"
            with open(outfilename, "w") as fp:
                json.dump(cbtable.serialize(), fp, indent=2)
            if showtags:
                outfilename = xout + "_tags.json"
                cbtags = cbtable.tags()
                if len(cbtags) > 0:
                    print("Call-back table tags (" + str(len(cbtags)) + ")")
                    print("------------------------------")
                    for t in sorted(cbtags):
                        print("  " + t)
                    dresult: Dict[str, List[str]] = {}
                    dresult["tags"] = cbtags
                    with open(outfilename, "w") as fp:
                        json.dump(dresult, fp, indent=2)
            exit(0)
        else:
            print_error("Callback table address not found: " + addr)
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
                    if len(callargs) > 1:
                        results[ctgt].setdefault(str(callargs[0]), 0)
                        results[ctgt][str(callargs[0])] += 1

    print("\nFiles opened by " + xname + ":")
    print("-" * 80)
    for tgt in results:
        for c in sorted(results[tgt]):
            print(str(results[tgt][c]).rjust(5) + "  " + c)

    exit(0)


def results_struct_arguments(args: argparse.Namespace) -> NoReturn:
    """Prints out a list of constant structs referred to in call arguments.

    Note: experimental, format will change.
    """

    # arguments
    xname: str = str(args.xname)
    optfname: Optional[str] = args.fname

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    results: Dict[int, Tuple[int, "BCCompInfo"]] = {}
    callinstrs = app.call_instructions()
    for faddr in callinstrs:
        for (baddr, instrs) in callinstrs[faddr].items():
            fn = app.function(faddr)
            finfo = fn.finfo
            for instr in instrs:
                iaddr = instr.iaddr
                if finfo.has_call_target_info(iaddr):
                    ctinfo = finfo.call_target_info(iaddr)
                    fname = ctinfo.target_interface.name
                    if optfname and optfname != fname:
                        continue
                    ftype = ctinfo.target_interface.bctype
                    if ftype is None:
                        continue
                    if not ftype.is_function:
                        continue
                    ftype = cast("BCTypFun", ftype)
                    funargs = ftype.argtypes
                    if funargs is None:
                        continue
                    callargs = instr.call_arguments
                    if len(callargs) == len(funargs.funargs):
                        for (funarg, x) in zip(funargs.funargs, callargs):
                            if not x.is_int_constant:
                                continue
                            if not funarg.typ.is_pointer:
                                continue
                            funargtyp = cast("BCTypPtr", funarg.typ)
                            if not funargtyp.tgttyp.is_struct:
                                continue
                            if funargtyp.tgttyp.is_typedef:
                                funargtgt = cast("BCTypNamed", funargtyp.tgttyp)
                                funargtgtdef = funargtgt.typedef
                                if funargtgtdef is None:
                                    continue
                                structtype = funargtgtdef.ttype
                            else:
                                structtype = funargtyp.tgttyp

                            structtype = cast("BCTypComp", structtype)
                            addr = x.intvalue
                            elfsection = app.header.get_elf_section_index(addr)
                            if elfsection is not None:
                                print(
                                    "struct: "
                                    + structtype.compname
                                    + " at "
                                    + str(x))
                                if addr not in results:
                                    results[addr] = (
                                        elfsection, structtype.compinfo)

    for (addr, (elfsection, compinfo)) in sorted(results.items()):
        print("\nstruct " + compinfo.cname + " at " + hex(addr))
        for (foffset, fieldinfo) in compinfo.fieldoffsets():
            fieldval = app.header.get_doubleword_value(elfsection, addr + foffset)
            print(
                str(foffset).rjust(4)
                + "  "
                + fieldinfo.fieldname
                + ": "
                + hex(fieldval))
            if fieldinfo.fieldtype.is_pointer:
                fieldtype = cast("BCTypPtr", fieldinfo.fieldtype)
                if (
                        fieldtype.tgttyp.is_integer
                        and fieldtype.tgttyp.byte_size() == 1):
                    fieldsection = app.header.get_elf_section_index(fieldval)
                    if fieldsection is not None:
                        fieldstring = app.header.get_string(
                            fieldsection, fieldval)
                        print("     Constant string: " + fieldstring)

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
    xoutput: str = args.output
    xformat: str = args.format
    xjson: bool = args.json
    xview: bool = args.view
    xpredicates: bool = args.predicates
    xcalls: bool = args.calls
    xnops: bool = args.nops
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

    outputfilename: Optional[str] = None
    if xjson:
        if xoutput is not None:
            outputfilename = xoutput + ".json"
    else:
        if xoutput is None:
            print_error("Please specify an output filename with --output/-o")
            exit(1)

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

        invariants = f.invariants
        nodecolors: Dict[str, str] = {}
        for b in f.blocks:
            if b in invariants:
                if any(k.is_unreachable for k in invariants[b]):
                    nodecolors[b] = "grey"

            if xnops:
                if f.instruction(b).is_nop_instruction:
                    nodecolors[b] = "yellow"

        if xjson:
            fresult = JU.function_cfg_to_json_result(f)
            if fresult.is_ok:
                jsonokresult = JU.jsonok("controlflowgraph", fresult.content)
                if outputfilename is not None:
                    with open(outputfilename, "w") as fp:
                        json.dump(jsonokresult, fp)
                else:
                    print(json.dumps(jsonokresult))
            exit(0)

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
            nodecolors=nodecolors,
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

        pdffilename = UD.print_dot(app.path, xoutput, dotcfg.build(), fileformat=xformat)

        if xderivedgraph:
            graphseq = f.cfg.derived_graph_sequence
            graphseq.to_dot(app.path, xfile + "_graphseq_" + faddr)

        if xsave_edges:
            edges = f.cfg.edges
            jsonfile = os.path.join(app.path, xoutput) + ".json"
            with open(jsonfile, "w") as fp:
                json.dump(edges, fp, indent=2)

        if os.path.isfile(pdffilename):
            print_info(
                "Control flow graph for "
                + fname
                + " has been saved in "
                + pdffilename)
        else:
            print_error("Error in converting dot file to pdf: " + pdffilename)
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


def show_var_invariant_table(args: argparse.Namespace) -> NoReturn:

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

        print(f.varinvdictionary.var_invariant_fact_table_to_string())

        print("Location invariants")
        print("-------------------")
        varinvariants = f.var_invariants
        for loc in sorted(varinvariants):
            print(loc)
            for vfact in varinvariants[loc]:
                print("  " + str(vfact))
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


def show_type_constraint_table(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    tcdictionary = app.tcdictionary

    constraints = [
        str(tc) for tc in tcdictionary.type_constraints()
        if not tc.is_var_constraint]

    for tc in sorted(constraints):
        print(tc)

    print("\n\n")

    print(str(app.type_constraints))

    exit(0)


def show_type_table(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    bcdictionary = app.bcdictionary

    print(bcdictionary.typ_table_to_string())

    exit(0)


def show_compinfo_table(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    bcdictionary = app.bcdictionary

    print(bcdictionary.compinfo_table_to_string())

    exit(0)


def show_function_interface_table(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    ixdictionary = app.interfacedictionary

    print(ixdictionary.function_interface_table_to_string())

    exit(0)


def show_function_semantics_table(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    ixdictionary = app.interfacedictionary

    print(ixdictionary.function_semantics_table_to_string())

    exit(0)


def ddata_gvars(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = str(args.xname)

    try:
        (path, xfile) = get_path_filename(xname)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    memmap = app.globalmemorymap
    glocs = memmap.locations

    print("Defined locations")
    for gaddr in sorted(glocs, key=lambda g: int(g, 16)):
        pgrefs: Dict[str, int] = {}   # count identical grefs
        gloc = glocs[gaddr]
        gtype = gloc.gtype
        if gtype is not None:
            sgtype = str(gtype)
        else:
            sgtype = ""
        if gloc.is_volatile:
            vt = " (volatile)"
        else:
            vt = ""
        print(gloc.addr.rjust(8)
              + "  "
              + gloc.name.ljust(60)
              + "  "
              + sgtype.ljust(20)
              + vt)

    (count, coverage) = memmap.coverage()

    print("\nNumber of locations: " + str(len(glocs)))
    print("Coverage: " + str(coverage) + " (typed: " + str(count) + ")")

    exit(0)


def ddata_userdata(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = str(args.xname)
    xoutput: str = str(args.output)

    try:
        (path, xfile) = get_path_filename(xname)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)

    result: Dict[str, Dict[str, Dict[str, str]]] = {}
    userdata = result["userdata"] = {}
    fnnames = userdata["function-names"] = {}
    symaddrs = userdata["symbolic-addresses"] = {}

    functionsdata = app.systeminfo.functionsdata.functions
    for (faddr, fdata) in sorted(functionsdata.items(), key=lambda t: int(t[0], 16)):
        if fdata.has_name():
            fnnames[faddr] = fdata.name

    memmap = app.globalmemorymap
    glocs = memmap.locations
    for gaddr in sorted(glocs, key=lambda g: int(g, 16)):
        gloc = glocs[gaddr]
        if gloc.gtype is not None:
            symaddrs[gaddr] = gloc.name

    with open(xoutput, "w") as fp:
        json.dump(result, fp, indent=4)

    print("\nSaved userdata with "
          + str(len(fnnames))
          + " function names and "
          + str(len(symaddrs))
          + " symbolic addresses")

    exit(0)


def ddata_md5s(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = str(args.xname)

    try:
        (path, xfile) = get_path_filename(xname)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)
    md5s = app.function_md5s

    result: Dict[str, int] = {}

    for md5 in md5s.values():
        result.setdefault(md5, 0)
        result[md5] += 1

    print("Number of functions: " + str(len(md5s)))
    print("Distinct md5s      : " + str(len(result)))

    for (md5, count) in result.items():
        if count > 10:
            print(md5 + ": " + str(count))

    exit(0)


def ddata_srcmap(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = str(args.xname)

    try:
        (path, xfile) = get_path_filename(xname)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = get_app(path, xfile, xinfo)
    srcmap = app.bcfiles.srcmap

    result: Dict[str, Dict[int, Tuple[str, str]]] = {}

    for (fname, linenr, vname, binloc) in srcmap:
        result.setdefault(fname, {})
        result[fname][linenr] = (vname, binloc)

    for fname in result:
        print(fname)
        for (linenr, (vname, binloc)) in sorted(result[fname].items()):
            print(str(linenr).rjust(6) + ": " + binloc.rjust(10) + "  " + vname)

    exit(0)
