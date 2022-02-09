# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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
"""Provides the local variables of a function."""

from typing import Any, Dict, List, Optional, TYPE_CHECKING

import xml.etree.ElementTree as ET

from chb.bctypes.BCVarInfo import BCVarInfo

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.bctypes.BCDictionary import BCDictionary
    from chb.bctypes.BCFiles import BCFiles


class BCFunctionDefinition:

    def __init__(self, bcfiles: "BCFiles", fname: str, xnode: ET.Element) -> None:
        """xnode is expected to be the <function> element."""

        self._bcfiles = bcfiles
        self._fname = fname
        self.local_varinfo_table = IT.IndexedTable("local-varinfo-table")
        self._localvars: Dict[str, BCVarInfo] = {}
        self.tables = [
            self.local_varinfo_table
        ]
        self.initialize(xnode)

    @property
    def bcfiles(self) -> "BCFiles":
        return self._bcfiles

    @property
    def bcd(self) -> "BCDictionary":
        return self.bcfiles.bcd

    @property
    def fname(self) -> str:
        return self._fname

    @property
    def formals(self) -> List[BCVarInfo]:
        result: List[BCVarInfo] = []
        for ix in self.local_varinfo_table.keys():
            vinfo = self.varinfo(ix)
            if vinfo.vparam > 0:
                result.append(vinfo)
        return result

    @property
    def localvars(self) -> Dict[str, BCVarInfo]:
        if len(self._localvars) == 0:
            for ix in self.local_varinfo_table.keys():
                vinfo = self.varinfo(ix)
                if vinfo.vparam == 0:
                    self._localvars[vinfo.vname] = vinfo
        return self._localvars

    def localvar(self, name: str) -> BCVarInfo:
        if name in self.localvars:
            return self.localvars[name]
        else:
            raise UF.CHBError(
                "Local variable "
                + name
                + " not found in function "
                + self.fname)

    def has_localvar(self, name: str) -> bool:
        return name in self.localvars

    def varinfo(self, ix: int) -> BCVarInfo:
        return BCVarInfo(self.bcd, self.local_varinfo_table.retrieve(ix))

    @property
    def svinfo(self) -> BCVarInfo:
        if not self._svinfo:
            raise UF.CHBError("BCFunctionDefinition: svinfo not found")
        return self._svinfo

    def initialize(self, xnode: ET.Element) -> None:
        xsvar = xnode.find("svar")
        if xsvar is None:
            raise UF.CHBError(
                "BCFunctionDefinition for " + self.fname + ": svar not found")
        ivinfo = int(xsvar.get("ivinfo", -1))
        if ivinfo == -1:
            raise UF.CHBError("BCFunctionDefinition: svar corrupted")
        self._svinfo = self.bcd.varinfo(ivinfo)
        xdecls = xnode.find("declarations")
        if xdecls is None:
            raise UF.CHBError("BCFunctionDefinition: declarations not found")
        for t in self.tables:
            xtable = xdecls.find(t.name)
            if xtable is not None:
                t.reset()
                t.read_xml(xtable, "n")
            else:
                raise UF.CHBError(
                    "Table " + t.name + " not found in function declarations")
