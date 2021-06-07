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

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.models.FunctionParameter import FunctionParameter
    from chb.models.SummaryCollection import SummaryCollection


class ParameterRepresentation:
    """Directive to represent a constant value with a name from a given enum set."""

    def __init__(
            self,
            fparam: "FunctionParameter",
            xnode: ET.Element) -> None:
        self._fparam = fparam
        self.xnode = xnode

    @property
    def summarycollection(self) -> "SummaryCollection":
        return self.parameter.summarycollection

    @property
    def parameter(self) -> "FunctionParameter":
        return self._fparam

    @property
    def type(self) -> str:
        xtype = self.xnode.get("type")
        if xtype:
            return xtype
        else:
            raise UF.CHBError("No type found for parameter representation of "
                              + self.parameter.name)

    @property
    def name(self) -> str:
        xname = self.xnode.get("name")
        if xname:
            return xname
        else:
            raise UF.CHBError("No name found for parameter representation of "
                              + self.parameter.name)

    @property
    def is_enum(self) -> bool:
        return self.type == "enum"

    def represent(self, v: int) -> str:
        if self.is_enum:
            enumrep = self.summarycollection.enum_constant(self.name, v)
            if enumrep:
                return enumrep
        return str(v)
