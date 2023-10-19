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

import chb.models.FunctionParameter as P
import chb.models.ModelsType as T
import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.models.FunctionPrecondition import FunctionPrecondition
    from chb.models.FunctionSummary import FunctionSummary
    from chb.models.SummaryCollection import SummaryCollection


class FunctionSignature:
    """Represents the signature of a function summary."""

    def __init__(self, fsum: "FunctionSummary", xnode: ET.Element) -> None:
        self._fsum = fsum
        self._xnode = xnode
        self._preconditions: Optional[List[FunctionPrecondition]] = None
        self.xcheck()

    @property
    def summarycollection(self) -> "SummaryCollection":
        return self.functionsummary.summarycollection

    @property
    def functionsummary(self) -> "FunctionSummary":
        return self._fsum

    @property
    def xnode(self) -> ET.Element:
        return self._xnode

    @property
    def name(self) -> str:
        xname = self.xnode.get("name")
        if xname:
            return xname
        else:
            raise UF.CHBError(
                "Name is missing in signature of function summary "
                + self.functionsummary.name)

    @property
    def is_varargs(self) -> bool:
        xvarargs = self.xnode.get("varargs")
        if xvarargs is not None:
            return xvarargs == "yes"
        return False

    @property
    def adjustment(self) -> int:
        xadj = self.xnode.get("adj")
        if xadj:
            return int(xadj)
        else:
            raise UF.CHBError(
                "Adjustment is missing in signature of function summary "
                + self.functionsummary.name)

    @property
    def calling_convention(self) -> str:
        xcc = self.xnode.get("cc")
        if xcc:
            return xcc
        else:
            raise UF.CHBError(
                "Calling convention is missing in signature of function summary "
                + self.functionsummary.name)

    @property
    def returntype(self) -> T.ModelsType:
        xty = self.xnode.find("returntype")
        if xty is not None:
            return T.mk_type(self, xty)
        else:
            raise UF.CHBError(
                "Function signature for "
                + self.name
                + " lacks a return type")

    @property
    def parameters(self) -> List[P.FunctionParameter]:
        xpars = self.xnode.findall("par")
        return [P.FunctionParameter(self, xpar) for xpar in xpars]

    @property
    def preconditions(self) -> List["FunctionPrecondition"]:
        if self._preconditions is None:
            self._preconditions = []
            for p in self.parameters:
                self._preconditions.extend(p.preconditions)
        return self._preconditions

    def xcheck(self) -> None:
        if (
                self.name != self.functionsummary.name
                and (self.name + "A") != self.functionsummary.name
                and (self.name + "W") != self.functionsummary.name):
            raise UF.CHBError(
                "Name discrepancy in function signature for "
                + self.functionsummary.name
                + " ("
                + self.name
                + ")")

    def __str__(self) -> str:
        lines: List[str] = []
        xchartype = self.functionsummary.char_type
        lines.append(str(self.returntype) + " " + self.functionsummary.name + "(")
        for p in self.parameters:
            lines.append("  " + str(p))
        if len(xchartype) > 0:
            lines.append(") (" + xchartype + ")")
        else:
            lines.append(")")
        return "\n".join(lines)
