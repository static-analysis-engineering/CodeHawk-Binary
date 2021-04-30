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

import os
import zipfile
import xml.etree.ElementTree as ET

from typing import Dict, List, Optional

import chb.models.DllEnumDefinitions as E
import chb.models.FunctionSummary as F
import chb.models.SummaryCollection as C

from chb.util.Config import Config
import chb.util.fileutil as UF


class ModelsAccess(object):
    """Main entry point for library function summaries.

    The main summary collection is obtained from the configured
    bchummaries.jar. Other summary collections may be added via
    additional jarfiles, specified with depjars.
    """

    def __init__(self,
                 depjars: List[str] = []) -> None:
        """Initialize library models access with jarfile."""
        self.bchsummariesjarfilename = Config().summaries
        self.depjars = depjars
        self.bchsummaries = C.SummaryCollection(self, self.bchsummariesjarfilename)
        self.dependencies = [C.SummaryCollection(
            self, depjar) for depjar in self.depjars]

    @property
    def stats(self) -> str:
        lines: List[str] = []
        dlls = self.get_dlls()
        for jar in dlls:
            lines.append(jar.ljust(20) + str(len(dlls[jar])) + " dlls")
        return "\n".join(lines)

    def get_dlls(self) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        result["bchsummaries"] = self.bchsummaries.dlls
        for d in self.dependencies:
            result[d.jarfilename] = d.dlls
        return result

    def has_dll_function_summary(self, dll: str, fname: str) -> bool:
        if self.bchsummaries.has_dll_function_summary(dll, fname):
            return True
        for d in self.dependencies:
            if d.has_dll_function_summary(dll, fname):
                return True
        else:
            return False

    def get_dll_function_summary(self, dll: str, fname: str) -> F.FunctionSummary:
        if self.bchsummaries.has_dll_function_summary(dll, fname):
            return self.bchsummaries.get_dll_function_summary(dll, fname)
        for d in self.dependencies:
            if d.has_dll_function_summary(dll, fname):
                return d.get_dll_function_summary(dll, fname)
        raise UF.CHBError("No dll summary found for " + dll + ":" + fname)

    def has_dll(self, dll: str) -> bool:
        if self.bchsummaries.has_dll(dll):
            return True
        for d in self.dependencies:
            if d.has_dll(dll):
                return True
        return False

    def get_all_function_summaries_in_dll(self, dll: str) -> List[F.FunctionSummary]:
        if self.bchsummaries.has_dll(dll):
            return self.bchsummaries.get_all_function_summaries_in_dll(dll)
        for d in self.dependencies:
            if d.has_dll(dll):
                return d.get_all_function_summaries_in_dll(dll)
        raise UF.CHBError("Dll " + dll + " not found")

    def has_so_functions(self) -> bool:
        return True

    def has_so_function_summary(self, fname: str) -> bool:
        return self.bchsummaries.has_so_function_summary(fname)

    def get_so_function_summary(self, fname: str) -> F.FunctionSummary:
        return self.bchsummaries.get_so_function_summary(fname)

    def get_all_so_function_summaries(self) -> Dict[str, List[F.FunctionSummary]]:
        result: Dict[str, List[F.FunctionSummary]] = {}
        sosummaries = self.bchsummaries.get_all_so_function_summaries()
        result["bchsummaries"] = sosummaries
        for d in self.dependencies:
            if d.has_so_functions:
                result[d.jarfilename] = d.get_all_so_function_summaries()
        return result

    def get_enum_definitions(self) -> Dict[str, E.DllEnumDefinitions]:
        return self.bchsummaries.enumdefinitions

    def has_dll_enum_definition(self, name: str) -> bool:
        return self.bchsummaries.has_dll_enum_definition(name)

    def get_dll_enum_definition(self, name: str) -> Dict[str, E.DllEnumValue]:
        return self.bchsummaries.get_dll_enum_definition(name)
