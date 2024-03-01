# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2023 Aarno Labs LLC
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


def print_progress_update(m: str) -> None:
    sys.stderr.write("[chkx] " + m + "\n")


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
            exclude_debug: bool = True,
            elf: bool = False,
            mips: bool = False,
            arm: bool = False,
            power: bool = False,
            thumb: bool = False,
            savedatablocks: bool = False,
            ifilenames: List[str] = [],
            fns_no_lineq: List[str] = [],
            fns_exclude: List[str] = [],
            fns_include: List[str] = [],
            show_function_timing: bool = False,
            gc_compact: int = 0,
            lineq_instr_cutoff = 0,
            lineq_block_cutoff = 0,
            use_ssa: bool = False,
            include_arm_extension_registers: bool = False,
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
        self.power = power
        self.thumb = thumb
        self.exclude_debug = exclude_debug
        self.savedatablocks = savedatablocks
        self.hints = hints
        self.ifilenames = ifilenames
        self.config = Config()
        self.chx86_analyze = self.config.chx86_analyze
        self.chsummaries = self.config.summaries
        self.chheader = self.config.stdchheader
        self.fns_no_lineq = fns_no_lineq
        self.fns_exclude = fns_exclude
        self.fns_include = fns_include
        self.show_function_timing = show_function_timing
        self.gc_compact = gc_compact
        self.lineq_instr_cutoff = lineq_instr_cutoff
        self.lineq_block_cutoff = lineq_block_cutoff
        self.fnsanalyzed: List[str] = []
        self.use_ssa = use_ssa
        self.include_arm_extension_registers = include_arm_extension_registers

    # Extraction and directory preparation -------------------------------------

    def extract_executable(
            self,
            chcmd: str = "-extract",
            verbose: bool = False) -> int:
        """Extracts executable content into xml; returns error code."""
        cwd = os.getcwd()
        os.chdir(self.path)    # temporary change in directory
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
        if self.power:
            cmd.append("-power")
        if self.elf:
            cmd.append("-elf")
        if self.exclude_debug:
            cmd.append("-exclude_debug")
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

        os.chdir(cwd)    # return to original directory
        return p

    def save_extract(self) -> None:
        cwd = os.getcwd()
        os.chdir(self.path)   # temporary change in directory
        xdir = os.path.join(self.filename + ".ch", "x")
        tarfilename = self.filename + ".chx.tar.gz"
        if os.path.isfile(tarfilename):
            os.remove(tarfilename)
        tarcmd: List[str] = ["tar", "cfz", tarfilename, xdir]
        subprocess.call(tarcmd, cwd=self.path, stderr=subprocess.STDOUT)
        os.chdir(cwd)    # return to original directory

    # Disassembly --------------------------------------------------------------

    def disassemble(
            self,
            save_xml: bool = False,
            timeout: Optional[int] = None,
            verbose: bool = False,
            collectdiagnostics: bool = True,
            preamble_cutoff: int = 12,
            save_asm: str = "yes") -> None:
        cwd = os.getcwd()
        os.chdir(self.path)     # temporary change in directory
        cmd: List[str] = [self.chx86_analyze, "-summaries", self.chsummaries]
        cmd.extend(["-preamble_cutoff", str(preamble_cutoff)])
        for d in self.deps:
            cmd.extend(["-summaries", d])
        cmd.extend(["-ifile", self.chheader])
        for s in self.specializations:
            cmd.extend(["-specialization", s])
        if save_asm == "yes":
            cmd.append("-save_asm")
        if collectdiagnostics:
            cmd.append("-diagnostics")
        if self.mips:
            cmd.append("-mips")
        if self.arm:
            cmd.append("-arm")
        if self.power:
            cmd.append("-power")
        if self.elf:
            cmd.append("-elf")
        if verbose:
            cmd.append("-verbose")
        if self.thumb:
            cmd.append("-thumb")
        if self.savedatablocks:
            cmd.append("-set_datablocks")
        for d in self.deps:
            cmd.extend(["-summaries", d])
        for s in self.so_libraries:
            cmd.extend(["-so_library", s])
        for ifile in self.ifilenames:
            cmd.extend(["-ifile", ifile])
        if save_xml:
            cmd.append("-save_disassembly_status_in_xml")
        cmd.extend(["-disassemble", self.filename])
        print_progress_update(" ".join(cmd))
        if sys.version_info > (3, 0) and timeout:
            try:
                result = subprocess.call(
                    cmd,
                    stderr=sys.stderr,
                    timeout=timeout)
                print_progress_update("Exit code: " + str(result))
            except subprocess.TimeoutExpired:
                print_progress_update(str(cmd) + " timed out!")
        else:
            result = subprocess.call(cmd, stderr=subprocess.STDOUT)
            print_progress_update("Exit code: " + str(result))

        os.chdir(cwd)    # return to original directory

    # Analysis -----------------------------------------------------------------

    def analyze(
            self,
            analysisrepeats: int = 1,
            iterations: int = 10,
            extract: bool = False,
            verbose: bool = False,
            collectdiagnostics: bool = False,
            ignore_stable: bool = False,
            save_asm: bool = False,
            construct_all_functions: bool = False,
            mem: bool = False,
            timeout: Optional[int] = None,
            preamble_cutoff: int = 12) -> int:
        self.fnsanalyzed = []
        self._analysis_setup(extract)
        result = self._analyze_until_stable(
            analysisrepeats,
            iterations,
            ignore_stable,
            asm=save_asm,
            mem=mem,
            timeout=timeout,
            verbose=verbose,
            construct_all_functions=construct_all_functions,
            collectdiagnostics=collectdiagnostics,
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
        tags = [
            "settings",
            "data-blocks",
            "function-entry-points",
            "function-names",
            "non-returning-functions",
            "esp-adjustments",
            "variable-introductions"]
        children = [ET.Element(t) for t in tags]
        snode.extend(children)
        snode.extend(UX.create_xml_userdata(self.hints))
        with open(ufilename, "w") as fp:
            fp.write(UX.doc_to_pretty(tree))

    def _analysis_setup(self, extract: bool) -> None:
        if extract:
            self.extract_executable()

    def _get_results(self) -> Tuple[str, str, str]:
        xresults = UF.get_resultmetrics_xnode(self.path, self.filename)

        def rm_error_msg(msg: str) -> str:
            return (
                "Error in result metrics file for "
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
        r_update = (
            "iteration: "
            + str(index).rjust(2)
            + "; functions: "
            + str(fnsanalyzed).rjust(4)
            + "; rtime: "
            + str(rtime).rjust(6)
            + "; total-time: "
            + str(ttime).rjust(6))
        return (isstable, line, r_update)

    def _analysis_header(self) -> str:
        lines: List[str] = []
        columnwidths = [6, 10, 10, 10, 10, 10, 10, 10]
        header1 = [
            "run", "functions", "esp", "reads", "writes", "%coverage",
            "time", "total time"]
        header2 = [
            "", "analyzed", "%prec", "%prec", "%prec", "", "(sec)",
            "(sec)"]
        lines.append("-" * 80)
        lines.append(
            "".join([header1[i].center(columnwidths[i])
                     for i in range(len(columnwidths))]))
        lines.append(
            "".join([header2[i].center(columnwidths[i])
                     for i in range(len(columnwidths))]))
        lines.append("-" * 80)
        return "\n".join(lines)

    def _call_analysis(self, cmd: List[str], timeout: Optional[int] = None) -> int:
        if sys.version_info < (3, 0) and timeout is not None:
            try:
                result = subprocess.call(
                    cmd,
                    cwd=self.path,
                    stderr=sys.stderr,
                    timeout=timeout)
                return result
            except subprocess.TimeoutExpired:
                print(str(cmd) + " timed out (" + str(timeout) + ")!")
                return 600
        else:
            result = subprocess.check_call(
                cmd,
                cwd=self.path,
                stderr=sys.stderr)
            return result

    def _analyze_until_stable(
            self,
            analysisrepeats: int,
            iterations: int,
            ignore_stable: bool = False,
            asm: bool = False,
            mem: bool = False,
            timeout: Optional[int] = None,
            verbose: bool = False,
            construct_all_functions: bool = False,
            collectdiagnostics: bool = False,
            preamble_cutoff: int = 12) -> int:
        cwd = os.getcwd()
        os.chdir(self.path)   # temporary change in directory
        functionsjarfile = UF.get_functionsjar_filename(self.path, self.filename)
        analysisdir = UF.get_analysis_dir(self.path, self.filename)
        cmd = [self.chx86_analyze, "-summaries", self.chsummaries]
        cmd.extend(["-preamble_cutoff", str(preamble_cutoff)])
        cmd.extend(["-ifile", self.chheader])
        if self.elf:
            cmd.append("-elf")
        if self.mips:
            cmd.append("-mips")
        if self.arm:
            cmd.append("-arm")
        if self.thumb:
            cmd.append("-thumb")
        if self.power:
            cmd.append("-power")
        for d in self.deps:
            cmd.extend(["-summaries", d])
        for s in self.so_libraries:
            cmd.extend(["-so_library", s])
        for s in self.fns_no_lineq:
            cmd.extend(["-fn_no_lineq", s])
        for s in self.fns_exclude:
            cmd.extend(["-fn_exclude", s])
        for s in self.fns_include:
            cmd.extend(["-fn_include", s])
        for s in self.specializations:
            cmd.extend(["-specialization", s])
        if analysisrepeats > 1:
            cmd.extend(["-analysisrepeats", str(analysisrepeats)])
        if ignore_stable:
            cmd.append("-ignore_stable")
        if verbose:
            cmd.append("-verbose")
        if collectdiagnostics:
            cmd.append("-diagnostics")
        if asm:
            cmd.append("-save_asm")
        if construct_all_functions:
            cmd.append("-construct_all_functions")
        if self.show_function_timing:
            cmd.append("-show_function_timing")
        if self.gc_compact > 0:
            cmd.extend(["-gc_compact", str(self.gc_compact)])
        if self.lineq_instr_cutoff > 0:
            cmd.extend(["-lineq_instr_cutoff", str(self.lineq_instr_cutoff)])
        if self.lineq_block_cutoff > 0:
            cmd.extend(["-lineq_block_cutoff", str(self.lineq_block_cutoff)])
        if self.include_arm_extension_registers:
            cmd.append("-arm_extension_registers")

        cmd.extend(["-analyze", self.filename])
        jarcmd = ["jar", "cf",  functionsjarfile, "-C", analysisdir, "functions"]
        print_progress_update("Analyzing "
              + self.filename
              + " (max "
              + str(iterations)
              + " iterations)")
        print_progress_update("executing: " + " ".join(cmd))

        lines: List[str] = []
        lines.append(self._analysis_header())
        firstcmd = cmd[:]
        for ifile in self.ifilenames:
            firstcmd.extend(["-ifile", ifile])
        result = self._call_analysis(firstcmd, timeout=timeout)
        if result != 0:
            os.chdir(cwd)   # return to original directory
            return result
        (isstable, results, r_update) = self._get_results()
        print_progress_update(r_update + "  " + self.filename)
        lines.append(results)

        count = 2
        while True:

            isfinished = (
                (isstable == "yes"
                 and not ignore_stable
                 and len(self.fns_include) == 0)
                or (count > iterations))

            if isfinished:
                subprocess.call(jarcmd, stderr=subprocess.STDOUT)
                fincmd = cmd + ["-collectdata"]
                if self.use_ssa:
                    fincmd = fincmd + ["-ssa"]
                result = self._call_analysis(fincmd, timeout=timeout)
                subprocess.call(jarcmd, stderr=subprocess.STDOUT)
                count += 1
                (stable, results, r_update) = self._get_results()
                print_progress_update(r_update + "  " + self.filename)
                lines.append(results)
                os.chdir(cwd)   # return to original directory
                print("\n".join(lines))
                return isstable == "yes"

            subprocess.call(jarcmd, stderr=subprocess.STDOUT)
            result = self._call_analysis(cmd, timeout=timeout)
            if result != 0:
                os.chdir(cwd)    # return to original directory
                print("\n".join(lines))
                return result

            count += 1
            (isstable, results, r_update) = self._get_results()
            print_progress_update(r_update + "  " + self.filename)
            lines.append(results)
