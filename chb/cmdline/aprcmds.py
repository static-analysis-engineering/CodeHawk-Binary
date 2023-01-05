# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2023  Aarno Labs, LLC
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
"""Commands related to producing patching data (automatic program repair)."""

import argparse
import json
import os

from typing import Any, Dict, List, NoReturn

import chb.apr.StackBufferOverflow as BOF
import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI

import chb.util.fileutil as UF


def patchdata(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    outputfile: str = args.outputfile
    callees: List[str] = args.callees

    if len(callees) == 0:
        UC.print_error("Please specify one or more callees")
        exit(1)

    try:
        (path, xfile) = UC.get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    patchinfo = BOF.get_patch_records(path, xfile, xinfo, callees)

    print("Found " + str(len(patchinfo)) + " patch records")

    results: Dict[str, Any] = {}
    results["file"] = xfile
    results["path"] = path
    results["patch-records"] = []
    for p in patchinfo:
        if p.has_size():
            results["patch-records"].append(p.to_dict())

    filename = os.path.join(path, outputfile + ".json")
    with open(filename, "w") as fp:
        json.dump(results, fp, indent=2)

    exit(0)
    
