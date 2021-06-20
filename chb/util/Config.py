# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma and Andrew McGraw
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
"""Contains the locations of various components used by the analyzer."""

import os

from typing import Any, Dict, List

localconfig = False

if os.path.isfile(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "ConfigLocal.py")):
    import chb.util.ConfigLocal as ConfigLocal
    localconfig = True


class Config():

    def __init__(self) -> None:
        # platform settings
        if os.uname()[0] == 'Linux':
            self.platform = 'linux'
        elif os.uname()[0] == 'Darwin':
            self.platform = 'macOS'

        # general settings
        self.utildir = os.path.dirname(os.path.abspath(__file__))
        self.chbdir = os.path.dirname(self.utildir)
        self.rootdir = os.path.dirname(self.chbdir)
        self.testsdir = os.path.join(self.rootdir, "tests")
        self.projects = os.path.join(self.testsdir, "projects.json")
        self.bindir = os.path.join(self.chbdir, "bin")
        self.binariesdir = os.path.join(self.bindir, "binaries")
        self.summariesdir = os.path.join(self.chbdir, "summaries")
        self.summaries = os.path.join(self.summariesdir, "bchsummaries.jar")

        # analyzer location
        if self.platform == 'linux':
            self.linuxdir = os.path.join(self.binariesdir, "linux")
            self.chx86_analyze = os.path.join(self.linuxdir, "chx86_analyze")

        elif self.platform == "macOS":
            self.macOSdir = os.path.join(self.binariesdir, "macOS")
            self.chx86_analyze = os.path.join(self.macOSdir, "chx86_analyze")

        # registered command-line options
        self.commandline_options: Dict[str, str] = {}

        # registered user data
        self.registered_userdata: Dict[str, str] = {}

        # personalization
        if localconfig:
            ConfigLocal.getLocals(self)

    def __str__(self) -> str:
        lines: List[str] = []
        analyzerfound = (
            " (found)" if os.path.isfile(self.chx86_analyze) else " (not found)")
        summariesfound = (
            " (found)" if os.path.isfile(self.summaries) else " (not found)")
        lines.append("Analyzer configuration:")
        lines.append("-----------------------")
        lines.append("  analyzer : " + self.chx86_analyze + analyzerfound)
        lines.append("  summaries: " + self.summaries + summariesfound)
        lines.append("")
        if len(self.commandline_options) > 0:
            lines.append("Projects with specified command-line options:")
            lines.append("---------------------------------------------")
            for (name, loc) in sorted(self.commandline_options.items()):
                lines.append(name + ": " + loc)
        return '\n'.join(lines)


if __name__ == '__main__':

    print(str(Config()))
