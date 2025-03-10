# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2025  Aarno Labs LLC
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

import os
import subprocess
import sys

from typing import List

from chb.util.Config import Config


class ASTCParseManager:

    def __init__(self) -> None:
        pass

    def check_cparser(self) -> bool:
        return os.path.isfile(Config().cparser)

    def preprocess_file_with_gcc(
            self, cfilename: str, moreoptions: List[str] = []) -> str:

        ifilename = cfilename[:-1] + "i"
        cmd = [
            "gcc",
            "-fno-inline",
            "-fno-builtin",
            "-E",
            "-g",
            "-o",
            ifilename,
            cfilename]
        cmd = cmd[:1] + moreoptions + cmd[1:]

        subprocess.call(
            cmd,
            cwd=os.getcwd(),
            stdout=open(os.devnull, "w"),
            stderr=subprocess.STDOUT,
        )
        return ifilename

    def parse_ifile(self, ifilename: str) -> int:
        cwd = os.getcwd()
        ifilename = os.path.join(cwd, ifilename)
        cmd = [Config().cparser, "-projectpath", cwd, "-targetdirectory", cwd]
        cmd.append(ifilename)
        p = subprocess.call(cmd, stderr=subprocess.STDOUT)
        sys.stdout.flush()
        return p
            
