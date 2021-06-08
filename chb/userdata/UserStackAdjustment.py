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

import chb.util.fileutil as UF


class UserStackAdjustment:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode

    @property
    def faddr(self) -> str:
        xfaddr = self.xnode.get("fa")
        if xfaddr is not None:
            return xfaddr
        else:
            raise UF.CHBError("Function address missing from stack adjustment")

    @property
    def iaddr(self) -> str:
        xiaddr = self.xnode.get("ia")
        if xiaddr is not None:
            return xiaddr
        else:
            raise UF.CHBError("Instruction address missing from stack adjustment")

    @property
    def adjustment(self) -> int:
        """Returns the number of bytes popped off the stack."""

        xadj = self.xnode.get("adj")
        if xadj is not None:
            return int(xadj)
        else:
            raise UF.CHBError("Stack adjustment missing from user record")

    def __str__(self) -> str:
        addr = self.faddr.ljust(10) + ',' + self.iaddr.ljust(10)
        return addr + ': ' + str(self.adjustment)
