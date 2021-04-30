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

import xml.etree.ElementTree as ET

from typing import Callable, Dict, List, TYPE_CHECKING

import chb.models.FunctionSummary as F

import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.models.SummaryCollection


class FunctionSummaryLibrary:
    "Represents function summaries from a single dll or SO library."""

    def __init__(self,
                 summarycollection: "chb.models.SummaryCollection.SummaryCollection",
                 directory: str,
                 name: str) -> None:
        self._name = name
        self._directory = directory
        self._summarycollection = summarycollection
        self.has_all_summaries: bool = False
        self._functionsummaries: Dict[str, F.FunctionSummary] = {}

    @property
    def name(self) -> str:
        return self._name

    @property
    def directory(self) -> str:
        return self._directory

    @property
    def summarycollection(self) -> "chb.models.SummaryCollection.SummaryCollection":
        return self._summarycollection

    @property
    def is_dll(self) -> bool:
        return False

    @property
    def is_shared_object(self) -> bool:
        return False

    @property
    def is_jni_library(self) -> bool:
        return False

    @property
    def libfun_xmltag(self) -> str:
        return "libfun"

    @property
    def is_jni(self) -> bool:
        return False

    def has_function_summary(self, fname: str) -> bool:
        if fname in self._functionsummaries:
            return True
        fsummary = self.summarycollection.retrieve_function_summary(self, fname)
        if fsummary:
            self._functionsummaries[fname] = fsummary
        return fname in self._functionsummaries

    def get_function_summary(self, fname: str) -> F.FunctionSummary:
        if self.has_function_summary(fname):
            return self._functionsummaries[fname]
        raise UF.CHBError("No function summary found for "
                          + self.name
                          + ", "
                          + fname)

    def get_all_function_summaries(self) -> List[F.FunctionSummary]:
        self.load_all_summaries()
        return list(self._functionsummaries.values())

    def iter(self, f: Callable[[str, F.FunctionSummary], None]) -> None:
        self.load_all_summaries()
        for fname in sorted(self._functionsummaries):
            f(fname, self._functionsummaries[fname])

    def load_all_summaries(self) -> None:
        if not self.has_all_summaries:
            fsummaries = self.summarycollection.retrieve_all_function_summaries(self)
            for fsum in fsummaries:
                self._functionsummaries[fsum.name] = fsum
            self.has_all_summaries = True
