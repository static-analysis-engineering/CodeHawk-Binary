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
    import chb.models.FunctionParameter


class ParameterRole:

    def __init__(
            self,
            fparam: "chb.models.FunctionParameter.FunctionParameter",
            xnode: ET.Element):
        self._fparam = fparam
        self.xnode = xnode

    @property
    def parameter(self) -> "chb.models.FunctionParameter.FunctionParameter":
        return self._fparam

    @property
    def is_ioc(self) -> bool:
        return self.role_type[:4] == "ioc"

    @property
    def role_type(self) -> str:
        xrt = self.xnode.get("rt")
        if xrt:
            return xrt
        else:
            raise UF.CHBError("Parameter "
                              + self.parameter.name
                              + " does not have a role type")

    @property
    def role_name(self) -> str:
        xrn = self.xnode.get("rn")
        if xrn:
            return xrn
        else:
            raise UF.CHBError("Parameter "
                              + self.parameter.name
                              + " does not have a role name")

    @property
    def ioc_name(self) -> str:
        if self.is_ioc:
            return self.role_type[4:]
        else:
            raise UF.CHBError("Parameter "
                              + self.parameter.name
                              + " is not a designated ioc: "
                              + str(self))

    def __str__(self) -> str:
        return ('(' + self.role_type + ',' + self.role_name + ')')
