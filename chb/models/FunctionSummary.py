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

from typing import Optional, TYPE_CHECKING

import chb.models.APIDoc as A
import chb.models.FunctionSignature as F
import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.models.FunctionSummaryLibrary
    import chb.models.SummaryCollection


class FunctionSummary:
    "Signature and summary semantics for a function."""

    def __init__(self,
                 library: "chb.models.FunctionSummaryLibrary.FunctionSummaryLibrary",
                 name: str,
                 xnode: ET.Element) -> None:
        self._name = name
        self._library = library
        self.xnode = xnode
        self._signature: Optional[F.FunctionSignature] = None

    @property
    def summarycollection(self) -> "chb.models.SummaryCollection.SummaryCollection":
        return self.library.summarycollection

    @property
    def library(self) -> "chb.models.FunctionSummaryLibrary.FunctionSummaryLibrary":
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
            raise UF.CHBError("Documentation is missing from function summary for "
                              + self.name)

    @property
    def char_type(self) -> str:
        """Return ANSI/UNICODE for A/W functions."""
        return ""

    @property
    def signature(self) -> F.FunctionSignature:
        if self._signature is None:
            xapi = self.xnode.find("api")
            if xapi:
                self._signature = F.FunctionSignature(self, xapi)
            else:
                raise UF.CHBError("No api element found in summary for "
                                  + self.name)
        return self._signature

    def __str__(self) -> str:
        try:
            return str(self.signature)
        except UF.CHBError as e:
            print("Error in function summary " + self.name)
            print(str(e.wrap()))
            exit(1)
