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

from typing import TYPE_CHECKING

import chb.models.FunctionSignature as S
import chb.models.FunctionSummary as F
import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.models.FunctionSummaryLibrary


class FunctionSummaryRef(F.FunctionSummary):

    def __init__(
            self,
            flib: "chb.models.FunctionSummaryLibrary.FunctionSummaryLibrary",
            name: str,
            xnode: ET.Element) -> None:
        F.FunctionSummary.__init__(self, flib, name, xnode)

    @property
    def xref(self) -> ET.Element:
        xref = self.xnode.find("refer-to")
        if xref is not None:
            return xref
        else:
            raise UF.CHBError("No refer-to node found in " + self.name)

    @property
    def refname(self) -> str:
        return self.xref.get("name", self.name)

    @property
    def reflib(self) -> str:
        return self.xref.get("lib", self.library_name)

    @property
    def refxnode(self) -> ET.Element:
        raise UF.CHBError("FunctionSummary.refxnode is abstract")

    @property
    def char_type(self) -> str:
        xchartype = self.xref.get("char-type")
        if xchartype:
            return xchartype
        else:
            return ""

    @property
    def signature(self) -> S.FunctionSignature:
        if self._signature is None:
            refxnode = self.refxnode
            xapi = self.refxnode.find("api")
            if xapi:
                self._signature = S.FunctionSignature(self, xapi)
            else:
                raise UF.CHBError("No api element found in summary reference for "
                                  + self.name)
        return self._signature
