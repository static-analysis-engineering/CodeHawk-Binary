# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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

from chb.models.FunctionPrecondition import (
    FunctionPrecondition, preconditionregistry)

from typing import List, Optional, TYPE_CHECKING

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.models.FunctionSummary import FunctionSummary


class FunctionSemantics:
    """Pre- and postconditions and sideeffects of a function."""

    def __init__(self, fsum: "FunctionSummary", xnode: ET.Element) -> None:
        self._fsum = fsum
        self._xnode = xnode
        self._preconditions: Optional[List[FunctionPrecondition]] = None

    @property
    def functionsummary(self) -> "FunctionSummary":
        return self._fsum

    @property
    def preconditions(self) -> List[FunctionPrecondition]:
        if self._preconditions is None:
            self._preconditions = []
            self._preconditions.extend(
                self.functionsummary.signature.preconditions)
            xprec = self._xnode.find("preconditions")
            if xprec is not None:
                xprecs = xprec.findall("pre")
                for xpre in xprecs:
                    pre = preconditionregistry.mk_instance(
                        self, xpre, FunctionPrecondition)
                    self._preconditions.append(pre)
        return self._preconditions

    def associated_preconditions(
            self, paramname: str) -> List[FunctionPrecondition]:
        """Return a list of preconditions that references paramname."""

        return [
            pre for pre in self.preconditions
            if pre.refers_to_parameter(paramname)]

    def parameter_roles(self, paramname: str) -> List[str]:
        """Return a list of roles that the parameter plays in preconditions."""

        result: List[str] = []
        for pre in self.associated_preconditions(paramname):
            result.extend(pre.parameter_roles(paramname))
        return result

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("\nPreconditions")
        for pre in self.preconditions:
            lines.append(str(pre))
        return "\n".join(lines)
