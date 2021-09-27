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
"""Main interface with the Ocaml analyzer.

The AnalysisManager object provides the functionality to invoke the ocaml
analyzer; it creates the necessary input files and collects the command-line
options according to the commands given via the command-line interpreter.
"""

import os
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from typing import Any, Dict, List, Optional, Tuple

from chb.util.Config import Config

import chb.util.fileutil as UF
import chb.util.xmlutil as UX


class AnalysisManager(object):
    """Sets up the command-line arguments for and invokes the Binary Analyzer."""

    def __init__(
            self,
            path: str,
            filename: str,
            xsize: int,
            deps: List[str] = [],
            so_libraries: List[str] = [],
            specializations: List[str] = [],
            elf: bool = False,
            mips: bool = False,
            arm: bool = False,
            thumb: bool = False,
            no_lineq: List[str] = [],
            hints: Dict[str, Any] = {}) -> None:
        """Initializes the analyzer location and target file location

        Arguments:
        - path: path of the directory that holds the target executable
        - filename: filename of the target executable
        - deps: list of summary jars
        - hints: Dictionary with items to add to the userdata file
        - elf/mips/arm: modifiers (default is x86 PE)
        """
        self.path = path
        self.filename = filename
        self.xsize = xsize
        self.deps = deps
        self.so_libraries = so_libraries
        self.specializations = specializations
        self.elf = elf
        self.mips = mips
        self.arm = arm
        self.thumb = thumb
        self.hints = hints
        self.config = Config()
        self.chx86_analyze = self.config.chx86_analyze
        self.chsummaries = self.config.summaries
        self.no_lineq = no_lineq
        self.fnsanalyzed: List[str] = []

    # Extraction and directory preparation -------------------------------------

    def extract_executable(
            self,
            chcmd: str = "-extract",
            verbose: bool = False) -> int:
        """Extracts executable content into xml; returns error code."""
        os.chdir(self.path)
        xdir = UF.get_executable_dir(self.path, self.filename)
        self._makedir(xdir)

        # create userdata directory
        udir = UF.get_userdata_dir(self.path, self.filename)
        fndir = os.path.join(udir, "functions")
        self._makedir(udir)
        self._makedir(fndir)
        # self._make_userdata_file()

        cmd: List[str] = [
            self.chx86_analyze,
            chcmd,
            "-xsize", str(self.xsize),
            "-summaries",
            self.chsummaries]
        if self.mips:
            cmd.append("-mips")
        if self.arm:
            cmd.append("-arm")
        if self.elf:
            cmd.append("-elf")
        if verbose:
            cmd.append("-verbose")
        for d in self.deps:
            cmd.extend(["-summaries", d])
        for s in self.so_libraries:
            cmd.extend(["-so_library", s])
        cmd.append(self.filename)
        p = subprocess.call(cmd, stderr=subprocess.STDOUT)
        if not (p == 0):
            shutil.rmtree(os.path.join(self.filename + ".ch", "x"))
            return p

        # create analysis directory
        adir = UF.get_analysis_dir(self.path, self.filename)
        fndir = os.path.join(adir, "functions")
        self._makedir(adir)
        self._makedir(fndir)

        # create results directory
        rdir = UF.get_results_dir(self.path, self.filename)
        fndir = os.path.join(rdir, "functions")
        self._makedir(rdir)
        self._makedir(fndir)

        return p

    def save_extract(self) -> None:
        os.chdir(self.path)
        xdir = os.path.join(self.filename + ".ch", "x")
        tarfilename = self.filename + ".chx.tar.gz"
        if os.path.isfile(tarfilename):
            os.remove(tarfilename)
        tarcmd: List[str] = ["tar", "cfz", tarfilename, xdir]
        subprocess.call(tarcmd, cwd=self.path, stderr=subprocess.STDOUT)

    # Disassembly --------------------------------------------------------------

    def disassemble(
            self,
            save_xml: bool = False,
            timeout: Optional[int] = None,
            verbose: bool = False,
            preamble_cutoff: int = 12,
            save_asm: str = "yes") -> None:
        os.chdir(self.path)
        cmd: List[str] = [self.chx86_analyze, "-summaries", self.chsummaries]
        cmd.extend(["-preamble_cutoff", str(preamble_cutoff)])
        for d in self.deps:
            cmd.extend(["-summaries", d])
        for s in self.specializations:
            cmd.extend(["-specialization", s])
        if save_asm == "yes":
            cmd.append("-save_asm")
        if self.mips:
            cmd.append("-mips")
        if self.arm:
            cmd.append("-arm")
        if self.elf:
            cmd.append("-elf")
        if verbose:
            cmd.append("-verbose")
        if self.thumb:
            cmd.append("-thumb")
        for d in self.deps:
            cmd.extend(["-summaries", d])
        for s in self.so_libraries:
            cmd.extend(["-so_library", s])
        if save_xml:
            cmd.append("-save_disassembly_status_in_xml")
        cmd.extend(["-disassemble", self.filename])
        print(cmd)
        if sys.version_info > (3, 0) and timeout:
            try:
                result = subprocess.call(
                    cmd,
                    stderr=subprocess.STDOUT,
                    timeout=timeout)
                print(result)
            except subprocess.TimeoutExpired:
                print(str(cmd) + " timed out!")
        else:
            result = subprocess.call(cmd, stderr=subprocess.STDOUT)
            print(result)

    # Analysis -----------------------------------------------------------------

    def analyze(
            self,
            iterations: int = 10,
            extract: bool = False,
            verbose: bool = False,
            ignore_stable: bool = False,
            save_asm: bool = False,
            mem: bool = False,
            timeout: Optional[int] = None,
            preamble_cutoff: int = 12) -> int:
        self.fnsanalyzed = []
        self._analysis_setup(extract)
        result = self._analyze_until_stable(
            iterations,
            ignore_stable,
            asm=save_asm,
            mem=mem,
            timeout=timeout,
            verbose=verbose,
            preamble_cutoff=preamble_cutoff)
        return result

    def _makedir(self, name: str) -> None:
        if os.path.isdir(name):
            return
        os.makedirs(name)

    def _make_userdata_file(self) -> None:
        ufilename = UF.get_user_system_data_filename(self.path, self.filename)
        root = UX.get_codehawk_xml_header(self.filename, "system-userdata")
        tree = ET.ElementTree(root)
        snode = ET.Element("system-info")
        root.append(snode)
        tags = ["settings",
                "data-blocks",
                "function-entry-points",
                "function-names",
                "non-returning-functions",
                "esp-adjustments"]
        children = [ET.Element(t) for t in tags]
        snode.extend(children)
        snode.extend(UX.create_xml_userdata(self.hints))
        with open(ufilename, "w") as fp:
            fp.write(UX.doc_to_pretty(tree))

    def _analysis_setup(self, extract: bool) -> None:
        if extract:
            self.extract_executable()

    def _get_results(self) -> Tuple[str, str]:
        xresults = UF.get_resultmetrics_xnode(self.path, self.filename)

        def rm_error_msg(msg: str) -> str:
            return ("Error in result metrics file for "
                    + os.path.join(self.path, self.filename)
                    + ": "
                    + msg)
        isstable = xresults.get("stable", "no")
        runs = xresults.find("runs")
        if not runs:
            raise UF.CHBError(rm_error_msg("Element runs not found"))
        run = runs[0]
        ftotals = xresults.find("function-totals")
        if ftotals is None:
            raise UF.CHBError(rm_error_msg("Element function-totals not found"))
        prec = ftotals.find("prec")
        if prec is None:
            raise UF.CHBError(rm_error_msg("Element prec not found"))
        disassembly = xresults.find("disassembly")
        if disassembly is None:
            raise UF.CHBError(rm_error_msg("Element disassembly not found"))
        index = run.get("index")
        fnsanalyzed = run.get("fns-analyzed", "0")
        self.fnsanalyzed.append(fnsanalyzed)
        esp = prec.get("esp")
        reads = prec.get("reads")
        writes = prec.get("writes")
        pcoverage = disassembly.get("pcoverage")
        rtime = run.get("time")
        ttime = xresults.get("time")
        columnwidths = [3, 10, 10, 10, 10, 10, 10, 10]
        r = [index, fnsanalyzed, esp, reads, writes, pcoverage, rtime, ttime]
        lines = [str(r[i]).rjust(columnwidths[i])
                 for i in range(len(columnwidths))]
        line = "".join(lines)
        if len(self.fnsanalyzed) == 4:
            if self.fnsanalyzed[0] == self.fnsanalyzed[3]:
                isstable = "yes"
            else:
                self.fnsanalyzed = self.fnsanalyzed[1:]
        return (isstable, line)

    def _print_analysis_header(self) -> None:
        columnwidths = [6, 10, 10, 10, 10, 10, 10, 10]
        header1 = ["run", "functions", "esp", "reads", "writes", "%coverage",
                   "time", "total time"]
        header2 = ["", "analyzed", "%prec", "%prec", "%prec", "", "(sec)",
                   "(sec)"]
        print("-" * 80)
        print("".join([header1[i].center(columnwidths[i])
                       for i in range(len(columnwidths))]))
        print("".join([header2[i].center(columnwidths[i])
                       for i in range(len(columnwidths))]))
        print("-" * 80)

    def _call_analysis(self, cmd: List[str], timeout: Optional[int] = None) -> int:
        if sys.version_info < (3, 0) and timeout is not None:
            try:
                result = subprocess.call(
                    cmd,
                    cwd=self.path,
                    stderr=subprocess.STDOUT,
                    timeout=timeout)
                return result
            except subprocess.TimeoutExpired:
                print(str(cmd) + " timed out (" + str(timeout) + ")!")
                return 600
        else:
            result = subprocess.check_call(
                cmd,
                cwd=self.path,
                stderr=subprocess.STDOUT)
            return result

    def _analyze_until_stable(
            self,
            iterations: int,
            ignore_stable: bool = False,
            asm: bool = False,
            mem: bool = False,
            timeout: Optional[int] = None,
            verbose: bool = False,
            preamble_cutoff: int = 12) -> int:
        os.chdir(self.path)
        functionsjarfile = UF.get_functionsjar_filename(self.path, self.filename)
        analysisdir = UF.get_analysis_dir(self.path, self.filename)
        cmd = [self.chx86_analyze, "-summaries", self.chsummaries]
        cmd.extend(["-preamble_cutoff", str(preamble_cutoff)])
        if self.elf:
            cmd.append("-elf")
        if self.mips:
            cmd.append("-mips")
        if self.arm:
            cmd.append("-arm")
        if self.thumb:
            cmd.append("-thumb")
        for d in self.deps:
            cmd.extend(["-summaries", d])
        for s in self.so_libraries:
            cmd.extend(["-so_library", s])
        for s in self.no_lineq:
            cmd.extend(["-no_lineq", s])
        for s in self.specializations:
            cmd.extend(["-specialization", s])
        if ignore_stable:
            cmd.append("-ignore_stable")
        if verbose:
            cmd.append("-verbose")
        if asm:
            cmd.append("-save_asm")
        cmd.extend(["-analyze", self.filename])
        jarcmd = ["jar", "cf",  functionsjarfile, "-C", analysisdir, "functions"]
        print("Analyzing "
              + self.filename
              + " (max "
              + str(iterations)
              + " iterations)")
        print(" ".join(cmd))
        self._print_analysis_header()
        result = self._call_analysis(cmd, timeout=timeout)
        if result != 0:
            return result
        (isstable, results) = self._get_results()
        print(results)

        count = 2
        while True:
            if isstable == "yes" and not ignore_stable:
                return True

            subprocess.call(jarcmd, stderr=subprocess.STDOUT)
            if count > iterations:
                return False

            result = self._call_analysis(cmd, timeout=timeout)
            if result != 0:
                return result

            count += 1
            (isstable, results) = self._get_results()
            print(results)
