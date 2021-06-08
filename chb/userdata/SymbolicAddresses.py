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

from typing import Dict, Mapping

import xml.etree.ElementTree as ET

import chb.util.fileutil as UF


class SymbolicAddress:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode

    @property
    def addr(self) -> str:
        xa = self.xnode.get("a")
        if xa is not None:
            return xa
        else:
            raise UF.CHBError("Address missing from symbolic address")

    @property
    def name(self) -> str:
        xname = self.xnode.get("name")
        if xname is not None:
            return xname
        else:
            raise UF.CHBError("Name missing from symbolic address")

    @property
    def size(self) -> int:
        xsize = self.xnode.get("size")
        if xsize is not None:
            return int(xsize)
        else:
            raise UF.CHBError("Size missing from symbolic address")


class SymbolicAddresses:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode
        self._addresses: Dict[str, SymbolicAddress] = {}

    def addresses(self) -> Mapping[str, SymbolicAddress]:
        if len(self._addresses) == 0:
            for x in self.xnode.findall("syma"):
                symaddr = SymbolicAddress(x)
                self._addresses[symaddr.addr] = symaddr
        return self._addresses

    def has_symbolic_address(self, addr: str) -> bool:
        return addr in self.addresses()

    def get_symbolic_address_name(self, addr: str) -> str:
        if addr in self.addresses():
            return self.addresses()[addr].name
        return addr
