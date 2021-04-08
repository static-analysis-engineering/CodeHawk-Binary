# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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
"""Utilities to print and save graphviz dot files."""

import os
import subprocess

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import chb.util.DotGraph


def print_dot(
        path: str,
        filename: str,
        g: "chb.util.DotGraph.DotGraph") -> str:
    if not os.path.isabs(filename):
        filename = os.path.join(path, filename)
    dotfilename = filename + ".dot"
    pdffilename = filename + ".pdf"

    # write graph to dot format
    with open(dotfilename,"w") as fp:
        fp.write(str(g))

    # convert dot file to pdf
    cmd = ["dot", "-Tpdf", "-o", pdffilename, dotfilename]
    try:
        subprocess.call(cmd,stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print("Error in processing dot file: " + dotfilename)
        print(e.output)
        print(e.args)
        exit(1)
    return pdffilename        


def save_dot(path: str, filename: str, g) -> None:
    if not os.path.isabs(filename):
        filename = os.path.join(path, filename)
    dotfilename = filename + ".dot"
    with open(dotfilename, "w") as fp:
        fp.write(str(g))


def save_svg(path: str, filename: str, g) -> None:
    if not os.path.isabs(filename):
        filename = os.path.join(path, filename)
    dotfilename = filename + ".dot"
    svgfilename = filename + ".svg"
    with open(dotfilename, "w") as fp:
        fp.write(str(g))
    cmd = ["dot", "-Tsvg", "-o", svgfilename, dotfilename]
    try:
        subprocess.call(cmd,stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print("Error in processing dot file: " + dotfilename)
        print(e.output)
        print(e.args)
        exit(1)
