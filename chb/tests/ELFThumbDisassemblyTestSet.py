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
"""Specification of unit tests for thumb disassembly."""

import os
import shutil
import subprocess

from typing import Dict, List

import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI

from chb.tests.ELFARMTestCreator import ELFARMTestCreator

import chb.util.fileutil as UF


tests = [
    ["MOV", "0446", "MOV", "R4, R0"],
    ["MOV", "0021", "MOVS", "R1, #0x0"]
]


class ELFThumbDisassemblyTestSet:

    def __init__(self) -> None:
        pass

    def create_test(self, r) -> None:
        files: Dict = {}
        name = r[0]
        tca = ELFARMTestCreator(name, r[1], suite="DT")
        elfheader = tca.create_elf_header()
        elfsection = tca.create_elf_section()
        xinfo = tca.create_xinfo()
        files["test_" + name + "_elf_header.xml"] = elfheader
        files["test_" + name + "_section_16.xml"] = elfsection

        UF.save_test_files(name, "arm32", "elf", "DT", name, files, xinfo)

    def remove_test(self, r) -> None:
        testfilename = UF.get_test_filename("arm32", "elf", "DT", r[0])
        (path, xfile) = UC.get_path_filename(testfilename)
        os.remove(os.path.join(path, xfile))
        shutil.rmtree(os.path.join(path, xfile + ".ch"))

    def run_test(self, r) -> None:
        testfilename = UF.get_test_filename("arm32", "elf", "DT", r[0])
        result = self.analyze_test_case(testfilename)
        if result != 0:
            print("Error in analysis of " + testfilename)

    def check_test(self, r) -> None:
        testfilename = UF.get_test_filename("arm32", "elf", "DT", r[0])
        try:
            (path, xfile) = UC.get_path_filename(testfilename)
        except UF.CHBError as e:
            print(str(e.wrap()))
            exit(1)

        xinfo = XI.XInfo()
        xinfo.load(path, xfile)

        app = UC.get_app(path, xfile, xinfo)
        if app.has_function("0x1000"):
            f = app.function("0x1000")
            instr = list(f.instructions.values())[0]
            mnemonic = instr.mnemonic
            ops = instr.operandstring
            refmnemonic = r[2]
            refopstring = r[3]
            if mnemonic != refmnemonic:
                print("Mismatch in mnemonic: " + mnemonic + ", " + refmnemonic)
            if ops != refopstring:
                print("Mismatch in operandstring: " + ops + ", " + refopstring)
            else:
                print(
                    "["
                    + r[0].ljust(8)
                    + r[1].ljust(10)
                    + r[2].ljust(8)
                    + r[3].ljust(12)
                    + "ok]")

    def analyze_test_case(self, filename: str) -> int:
        cmdprocessor = UF.get_command_processor()
        cmd: List[str] = [
            "python3",
            cmdprocessor,
            "analyze",
            filename,
            "--thumb",
            "0x1000:T",
            "--reset"]
        result = subprocess.call(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        return result

    def run(self):
        for r in tests:
            self.create_test(r)
            self.run_test(r)
            self.check_test(r)
            self.remove_test(r)
