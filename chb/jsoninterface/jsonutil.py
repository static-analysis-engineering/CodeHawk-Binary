# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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

import argparse
import json
import os

from typing import Any, Dict, List, NoReturn, Optional

from chb.jsoninterface.JSONAppComparison import JSONAppComparison
from chb.jsoninterface.JSONChecker import JSONChecker


def print_jsoninfo(d: Dict[str, Any]) -> None:
    meta = d.get("meta", {})
    print("status: ", meta.get("status", "fail"))
    print("date  : ", meta.get("date", "missing:meta:date"))
    print("time  : ", meta.get("time", "missing:meta:time"))
    print("schema: ", meta.get("schema", "missing:meta:schema"))
    print("version: ", meta.get("version", "missing:meta:version"))
    print("\nContent toplevel")
    for k in d.get("content", {}):
        print("  -" + k)
    print("-" * 80)


def infocmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    jsonfile: str = args.jsonfile

    with open(jsonfile, "r") as fp:
        jsondata = json.load(fp)

    print_jsoninfo(jsondata)

    exit(0)


def checkcmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    jsonfile: str = args.jsonfile
    level: int = args.level

    with open(jsonfile, "r") as fp:
        jsondata = json.load(fp)

    print(JSONChecker().check_object(JSONAppComparison(jsondata["content"])))

    exit(0)

          
