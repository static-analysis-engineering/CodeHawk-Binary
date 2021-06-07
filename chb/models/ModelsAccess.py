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

from typing import Dict, List, Mapping, Optional, Sequence

from chb.models.DllEnumDefinitions import DllEnumDefinitions, DllEnumValue
from chb.models.FunctionSummary import FunctionSummary
from chb.models.SummaryCollection import SummaryCollection

from chb.util.Config import Config
import chb.util.fileutil as UF


class ModelsAccess(object):
    """Main entry point for library function summaries.

    The main summary collection is obtained from the configured
    bchummaries.jar. Other summary collections may be added via
    additional jarfiles, specified with depjars.
    """

    def __init__(self,
                 depjars: Sequence[str] = []) -> None:
        """Initialize library models access with jarfile."""
        self._bchsummariesjarfilename = Config().summaries
        self._depjars = depjars
        self._bchsummaries: Optional[SummaryCollection] = None
        self._dependencies: Sequence[SummaryCollection] = []
        self._dlls: Dict[str, Sequence[str]] = {}
        self._sofunctionsummaries: Dict[str, Sequence[FunctionSummary]] = {}

    @property
    def depjars(self) -> Sequence[str]:
        return self._depjars

    @property
    def bchsummariesjarfilename(self) -> str:
        return self._bchsummariesjarfilename

    @property
    def bchsummaries(self) -> SummaryCollection:
        if self._bchsummaries is None:
            self._bchsummaries = SummaryCollection(
                self, self.bchsummariesjarfilename)
        return self._bchsummaries

    @property
    def dependencies(self) -> Sequence[SummaryCollection]:
        if len(self._dependencies) == 0:
            self._dependencies = [SummaryCollection(self, j) for j in self.depjars]
        return self._dependencies

    @property
    def stats(self) -> str:
        lines: List[str] = []
        dlls = self.dlls()
        for jar in dlls:
            lines.append(jar.ljust(20) + str(len(dlls[jar])) + " dlls")
        return "\n".join(lines)

    def dlls(self) -> Mapping[str, Sequence[str]]:
        """Return a mapping from jarfilename to list of function names."""

        if len(self._dlls) == 0:
            self._dlls["bchsummaries"] = self.bchsummaries.dlls
            for d in self.dependencies:
                self._dlls[d.jarfilename] = d.dlls
        return self._dlls

    def has_dll_function_summary(self, dll: str, fname: str) -> bool:
        if self.bchsummaries.has_dll_function_summary(dll, fname):
            return True
        for d in self.dependencies:
            if d.has_dll_function_summary(dll, fname):
                return True
        else:
            return False

    def dll_function_summary(self, dll: str, fname: str) -> FunctionSummary:
        if self.bchsummaries.has_dll_function_summary(dll, fname):
            return self.bchsummaries.dll_function_summary(dll, fname)
        for d in self.dependencies:
            if d.has_dll_function_summary(dll, fname):
                return d.dll_function_summary(dll, fname)
        raise UF.CHBError("No dll summary found for " + dll + ":" + fname)

    def has_dll(self, dll: str) -> bool:
        if self.bchsummaries.has_dll(dll):
            return True
        for d in self.dependencies:
            if d.has_dll(dll):
                return True
        return False

    def all_function_summaries_in_dll(self, dll: str) -> Sequence[FunctionSummary]:
        if self.bchsummaries.has_dll(dll):
            return self.bchsummaries.all_function_summaries_in_dll(dll)
        for d in self.dependencies:
            if d.has_dll(dll):
                return d.all_function_summaries_in_dll(dll)
        raise UF.CHBError("Dll " + dll + " not found")

    def has_so_functions(self) -> bool:
        return True

    def has_so_function_summary(self, fname: str) -> bool:
        return self.bchsummaries.has_so_function_summary(fname)

    def so_function_summary(self, fname: str) -> FunctionSummary:
        return self.bchsummaries.so_function_summary(fname)

    def all_so_function_summaries(self) -> Mapping[str, Sequence[FunctionSummary]]:
        """Return a mapping from jarfilename to list of function summaries."""

        if len(self._sofunctionsummaries) == 0:
            sosummaries = self.bchsummaries.all_so_function_summaries()
            self._sofunctionsummaries["bchsummaries"] = sosummaries
            for d in self.dependencies:
                if d.has_so_functions:
                    self._sofunctionsummaries[
                        d.jarfilename] = d.all_so_function_summaries()
        return self._sofunctionsummaries

    def enum_definitions(self) -> Mapping[str, DllEnumDefinitions]:
        return self.bchsummaries.enumdefinitions

    def has_dll_enum_definition(self, name: str) -> bool:
        return self.bchsummaries.has_dll_enum_definition(name)

    def dll_enum_definition(self, name: str) -> Mapping[str, DllEnumValue]:
        return self.bchsummaries.dll_enum_definition(name)
