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

from typing import Any, Dict, NoReturn, Optional

import chb.app.AppAccess as AP
import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI
import chb.util.fileutil as UF


def pedatacmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    headeronly: bool = args.headeronly
    imports: bool = args.imports
    headers: bool = args.headers
    sections: bool = args.sections
    section: Optional[str] = args.section

    try:
        (path, xfile) = UC.get_path_filename(xname)
        UC.prepare_executable(path, xfile, doreset=False, doresetx=False, hints=[])
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    if not xinfo.is_pe32:
        UC.print_error("File is not a PE32 file: " + xinfo.format)
        exit(1)

    app = UC.get_app(path, xfile, xinfo)
    peheader = app.header
    if headeronly:
        print(peheader)
        exit(0)
    if imports:
        for i in list(peheader.import_tables.values()):
            print(str(i))
        exit(0)
    if headers:
        for h in list(peheader.section_headers.values()):
            print(str(h))
        exit(0)
    if sections:
        for (name, s) in peheader.sections.items():
            print(str(s))
        exit(0)
    if section is not None:
        s = peheader.get_section(section)
        if s is None:
            UC.print_error(
                "Unable to find section at virtual address: "
                + str(section))
            exit(1)
        print(str(s))
        exit(0)
    print(peheader)
    for i in list(peheader.import_tables.values()):
        print(str(i))
    for h in list(peheader.section_headers.values()):
        print(str(h))
    exit(0)


def elfdatacmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    savesectionheaders: str = args.save_section_headers

    try:
        (path, xfile) = UC.get_path_filename(xname)
        UC.prepare_executable(path, xfile, doreset=False, doresetx=False, hints=[])
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    if not xinfo.is_elf:
        print("File is not an ELF file: " + xinfo.format)
        exit(1)

    app = UC.get_app(path, xfile, xinfo)
    # app = AP.AppAccess(
    #    path, xfile, fileformat=xinfo.format, arch=xinfo.architecture)
    elfheader = app.header

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
            result["section-headers"].append(s.attribute_values())
        filename = xname + "_section_headers.json"
        with open(filename, "w") as fp:
            json.dump(result, fp, indent=3)
        UC.print_info("Saved section headers in " + filename)

    exit(0)
