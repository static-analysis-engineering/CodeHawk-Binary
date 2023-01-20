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

from typing import Callable, Dict, List, Mapping, Sequence, Tuple

from chb.app.BDictionary import BDictionary

import chb.util.fileutil as UF


class StringXRefs:

    def __init__(self, bd: BDictionary, xnode: ET.Element) -> None:
        self.xnode = xnode
        self._bd = bd
        self._xrefs: List[Tuple[str, str]] = []     # (faddr,iaddr) list

    @property
    def bd(self) -> BDictionary:
        return self._bd

    @property
    def strval(self) -> str:
        return self.bd.read_xml_string(self.xnode)

    @property
    def addr(self) -> str:
        xaddr = self.xnode.get("a")
        if xaddr is not None:
            return xaddr
        else:
            raise UF.CHBError("Address missing from string reference")

    @property
    def xrefs(self) -> Sequence[Tuple[str, str]]:
        if len(self._xrefs) == 0:
            for x in self.xnode.findall("xref"):
                faddr = x.get("f")
                iaddr = x.get("ci")
                if faddr and iaddr:
                    self._xrefs.append((faddr, iaddr))
        return self._xrefs


class StringsXRefs(object):

    def __init__(self, bd: BDictionary, xnode: ET.Element) -> None:
        self._bd = bd
        self.xnode = xnode
        self._strings: Dict[str, StringXRefs] = {}  # hex-address -> StringXRefs

    @property
    def bd(self) -> BDictionary:
        return self._bd

    def strings(self) -> Mapping[str, StringXRefs]:
        if len(self._strings) == 0:
            for x in self.xnode.findall("string-xref"):
                xrefs = StringXRefs(self.bd, x)
                self._strings[xrefs.addr] = xrefs
        return self._strings

    def iter(self, f: Callable[[str, StringXRefs], None]) -> None:
        for (a, xref) in sorted(self.strings().items()):
            f(a, xref)

    def has_string(self, addr: str) -> bool:
        return addr in self.strings()

    def string(self, addr: str) -> str:
        if self.has_string(addr):
            return self.strings()[addr].strval
        else:
            raise UF.CHBError("No string found at address " + addr)

    def function_xref_strings(self) -> Mapping[str, Mapping[str, int]]:
        """Returns faddr -> strval -> count. """

        result: Dict[str, Dict[str, int]] = {}
        for (s, xref) in self.strings().items():
            strval = xref.strval
            for (faddr, iaddr) in xref.xrefs:
                result.setdefault(faddr, {})
                result[faddr].setdefault(strval, 0)
                result[faddr][strval] += 1
        return result

    def __str__(self) -> str:
        return str(len(self.function_xref_strings())) + " string references"
