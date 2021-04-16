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

from typing import Any, Dict, List, Optional, NoReturn, Tuple

import chb.app.AppAccess as AP
import chb.cmdline.AnalysisManager as AM
import chb.cmdline.UserHints as UH
import chb.cmdline.XInfo as XI
import chb.graphics.DotCfg as DC
import chb.util.dotutil as UD
import chb.util.fileutil as UF
import chb.util.xmlutil as UX


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


def setup_directories(path: str, xfile: str) -> None:
    """Create the x.ch directories."""
    def makedirc(name):
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
        hints: List[str],
        thumb: List[str]) -> None:
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

        if os.path.isdir(chdir) and doreset:
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
        if not (xinfo.is_x86()
                or xinfo.is_mips()
                or xinfo.is_arm()):
            raise UF.CHBError("Architecture "
                              + xinfo.architecture
                              + " not supported")
        if not (xinfo.is_pe32() or xinfo.is_elf()):
            raise UF.CHBError("File format "
                              + xinfo.format
                              + " not supported")

        # set up directories and user data
        setup_directories(path, xfile)
        setup_user_data(path, xfile, hints, thumb, xinfo.md5)
        xinfo.save(path, xfile)

        # extract executable content
        am = AM.AnalysisManager(
            path,
            xfile,
            mips=xinfo.is_mips(),
            arm=xinfo.is_arm(),
            elf=xinfo.is_elf())

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

    am = AM.AnalysisManager(
        path,
        xfile,
        mips=xinfo.is_mips(),
        arm=xinfo.is_arm(),
        elf=xinfo.is_elf(),
        thumb = (len(thumb) > 0))

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


def showstats(args: argparse.Namespace) -> NoReturn:
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

    app = AP.AppAccess(path, xfile, mips=xinfo.is_mips(), arm=xinfo.is_arm())
    stats = app.get_result_metrics()
    print(stats.header_to_string())
    for f in sorted(stats.get_function_results(),
                    key=lambda f: (f.get_espp(), f.faddr)):
        print(f.metrics_to_string(shownocallees=nocallees))
    print(stats.disassembly_to_string())
    print(stats.analysis_to_string())
    exit(0)


def showfunctions(args: argparse.Namespace) -> NoReturn:
    """Prints out annotated assembly listing of one or more functions."""

    # arguments
    xname: str = str(args.xname)
    functions: List[str] = args.functions
    hash: bool = args.hash
    bytestring: bool = args.bytestring
    opcodewidth: int = args.opcodewidth

    try:
        (path, xfile) = get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    app = AP.AppAccess(path, xfile, mips=xinfo.is_mips(), arm=xinfo.is_arm())
    if "all" in functions:
        fns: List[str] = sorted(app.get_function_addresses())
    else:
        fns = functions

    for faddr in fns:
        if app.has_function(faddr):
            f = app.get_function(faddr)
            if f is None:
                print_error("Unable to find function " + faddr)
                continue

            try:
                if app.has_function_name(faddr):
                    print("\nFunction "
                          + faddr
                          + " ("
                          + app.get_function_name(faddr)
                          + ")")
                else:
                    print("\nFunction " + faddr)
                print("-" * 80)

                if xinfo.is_mips() or xinfo.is_arm():
                    print(f.to_string(
                        bytestring=bytestring,
                        hash=hash,
                        sp=True,
                        opcodetxt=True,
                        opcodewidth=opcodewidth))
                else:
                    print(f.to_string(
                        bytestring=bytestring,
                        hash=hash,
                        esp=True,
                        opcodetxt=True,
                        opcodewidth=opcodewidth))
            except UF.CHBError as e:
                print(str(e.wrap()))
        else:
            print_error("Function " + faddr + " not found")
            continue
    exit(0)


def showcfg(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    faddr: str = args.faddr
    out: str = args.out
    xview: bool = args.view
    xpredicates: bool = args.predicates
    xcalls: bool = args.calls
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

    app = AP.AppAccess(path, xfile, mips=xinfo.is_mips(), arm=xinfo.is_arm())
    if app.has_function(faddr):
        f = app.get_function(faddr)
        if f is None:
            print_error("Unable to find function " + faddr)
            exit(1)
        graphname = "cfg_" + faddr
        if not xsink is None:
            graphname += "_" + xsink
        if len(xsegments) > 0:
            graphname += "_" + "_".join(xsegments)
        dotcfg = DC.DotCfg(
            graphname,
            f,
            looplevelcolors=["#FFAAAAFF","#FF5555FF","#FF0000FF"],
            showpredicates=xpredicates,
            showcalls=xcalls,
            mips=xinfo.is_mips(),
            sink=xsink,
            segments=xsegments)

        fname = faddr
        if app.has_function_name(faddr):
            fname = fname + " (" + app.get_function_name(faddr) + ")"

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


def showelfdata(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    savesectionheaders: str = args.save_section_headers

    try:
        (path, xfile) = get_path_filename(xname)
        prepare_executable(path, xfile, doreset=False, doresetx=False, hints=[])
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    if not xinfo.is_elf():
        print("File is not an ELF file: " + xinfo.format)
        exit(1)

    app = AP.AppAccess(path, xfile, initialize=False, mips=xinfo.is_mips())
    elfheader = app.get_elf_header()

    try:
        print(str(elfheader))
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    if savesectionheaders:
        result: Dict[str, Any] = {}
        result["file"] = xinfo.file
        result["md5"] = xinfo.md5
        result["section-headers"] = []
        for s in elfheader.sectionheaders:
            result["section-headers"].append(s.get_values())
        filename = xname + "_section_headers.json"
        with open(filename, "w") as fp:
            json.dump(result, fp, indent=3)
        print_info("Saved section headers in " + filename)

    exit(0)


def showpedata(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    headeronly: bool = args.headeronly
    imports: bool = args.imports
    headers: bool = args.headers
    sections: bool = args.sections
    section: Optional[str] = args.section

    try:
        (path, xfile) = get_path_filename(xname)
        prepare_executable(path, xfile, doreset=False, doresetx=False, hints=[])
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    if not xinfo.is_pe32():
        print_error("File is not a PE32 file: " + xinfo.format)
        exit(1)

    app = AP.AppAccess(path, xfile, initialize=False, mips=False)
    peheader = app.get_pe_header()
    if headeronly:
        print(peheader)
        exit(0)
    if imports:
        for i in peheader.get_import_tables():
            print(str(i))
        exit(0)
    if headers:
        for h in peheader.get_section_headers():
            print(str(h))
        exit(0)
    if sections:
        for s in peheader.get_sections():
            print(str(s))
        exit(0)
    if section is not None:
        s = peheader.get_section(section)
        if s is None:
            print_error("Unable to find section at virtual address: "
                        + section)
            exit(1)
        print(str(s))
        exit(0)
    print(peheader)
    for i in peheader.get_import_tables():
        print(str(i))
    for h in peheader.get_section_headers():
        print(str(h))
    exit(0)
