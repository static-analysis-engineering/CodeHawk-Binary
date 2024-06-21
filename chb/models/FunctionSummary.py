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

import xml.etree.ElementTree as ET

from typing import List, Optional, TYPE_CHECKING

import chb.models.APIDoc as A
from chb.models.FunctionSemantics import FunctionSemantics
from chb.models.FunctionSignature import FunctionSignature
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.models.FunctionSummaryLibrary import FunctionSummaryLibrary
    from chb.models.SummaryCollection import SummaryCollection


class FunctionSummary:
    "Signature and summary semantics for a function."""

    def __init__(self,
                 library: "FunctionSummaryLibrary",
                 name: str,
                 xnode: ET.Element) -> None:
        self._name = name
        self._library = library
        self.xnode = xnode
        self._signature: Optional[FunctionSignature] = None
        self._semantics: Optional[FunctionSemantics] = None

    @property
    def summarycollection(self) -> "SummaryCollection":
        return self.library.summarycollection

    @property
    def library(self) -> "FunctionSummaryLibrary":
        return self._library

    @property
    def library_name(self) -> str:
        return self._library.name

    @property
    def name(self) -> str:
        return self._name

    @property
    def api_documentation(self) -> A.APIDoc:
        xdoc = self.xnode.find("documentation")
        if xdoc is not None:
            return A.APIDoc(self, xdoc)
        else:
            raise UF.CHBError(
                "Documentation is missing from function summary for "
                + self.name)

    @property
    def char_type(self) -> str:
        """Return ANSI/UNICODE for A/W functions."""
        return ""

    @property
    def signature(self) -> FunctionSignature:
        if self._signature is None:
            xapi = self.xnode.find("api")
            if xapi:
                self._signature = FunctionSignature(self, xapi)
            else:
                raise UF.CHBError(
                    "No api element found in summary for " + self.name)
        return self._signature

    def parameter_index(self, name: str) -> Optional[int]:
        return self.signature.parameter_index(name)

    @property
    def semantics(self) -> FunctionSemantics:
        if self._semantics is None:
            xsem = self.xnode.find("semantics")
            if xsem is not None:
                self._semantics = FunctionSemantics(self, xsem)
            else:
                raise UF.CHBError(
                    "No semantics element found in summary for " + self.name)
        return self._semantics

    def __str__(self) -> str:
        lines: List[str] = []
        try:
            lines.append(str(self.signature))
            lines.append(str(self.semantics))
        except UF.CHBError as e:
            print("Error in function summary " + self.name)
            print(str(e.wrap()))
            exit(1)
        return "\n".join(lines)
