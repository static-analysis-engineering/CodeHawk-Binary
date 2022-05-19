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
"""Contains all global types in a CIL file."""

from typing import Any, Dict, List, Optional, TYPE_CHECKING

import xml.etree.ElementTree as ET

from chb.bctypes.BCCompInfo import BCCompInfo
from chb.bctypes.BCDictionary import BCDictionary
from chb.bctypes.BCFunctionDefinition import BCFunctionDefinition
from chb.bctypes.BCTyp import BCTyp
from chb.bctypes.BCTypeInfo import BCTypeInfo
from chb.bctypes.BCVarInfo import BCVarInfo

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess


class BCFiles:

    def __init__(self, app: "AppAccess", xnode: ET.Element) -> None:
        self._app = app
        self._gtypes: List[BCTyp] = []
        self._gcomptags: List[BCCompInfo] = []
        self._gvardecls: List[BCVarInfo] = []
        self._gvardefs: List[BCVarInfo] = []
        self._functions: Dict[str, BCFunctionDefinition] = {}
        self.initialize(xnode)

    @property
    def app(self) -> "AppAccess":
        return self._app

    @property
    def bcd(self) -> BCDictionary:
        return self.app.bcdictionary

    @property
    def gtypes(self) -> List[BCTyp]:
        return self._gtypes

    @property
    def gcomptags(self) -> List[BCCompInfo]:
        return self._gcomptags

    @property
    def gvardecls(self) -> List[BCVarInfo]:
        return self._gvardecls

    @property
    def gvardefs(self) -> List[BCVarInfo]:
        return self._gvardefs

    @property
    def globalvars(self) -> List[BCVarInfo]:
        return self._gvardefs + self._gvardecls

    @property
    def functions(self) -> Dict[str, BCFunctionDefinition]:
        return self._functions

    def functiondef(self, name: str) -> BCFunctionDefinition:
        if name.startswith("0x"):
            name = "sub_" + name[2:]
        if name in self.functions:
            return self.functions[name]
        else:
            raise UF.CHBError("Function definition " + name + " not found")

    def has_functiondef(self, name: str) -> bool:
        if name.startswith("0x"):
            return "sub_" + name[2:] in self.functions
        else:
            return name in self.functions

    def has_vardecl(self, name: str) -> bool:
        return any([vinfo.vname == name for vinfo in self.gvardecls])

    def vardecl(self, name: str) -> BCVarInfo:
        for vinfo in self.gvardecls:
            if vinfo.vname == name:
                return vinfo
        else:
            raise UF.CHBError(
                "Variable declaration for " + name + " not found")

    def has_compinfo(self, ckey: int) -> bool:
        return any([cinfo.ckey == ckey for cinfo in self.gcomptags])

    def compinfo(self, ckey: int) -> BCCompInfo:
        for cinfo in self.gcomptags:
            if cinfo.ckey == ckey:
                return cinfo
        else:
            raise UF.CHBError(
                "Compinfo with key " + str(ckey) + " not found")

    def initialize(self, xnode: ET.Element) -> None:
        self.initialize_compinfos(xnode.find("compinfos"))
        self.initialize_typeinfos(xnode.find("typeinfos"))
        self.initialize_vardefs(xnode.find("varinfos"))
        self.initialize_vardecls(xnode.find("varinfodecls"))
        self.initialize_functions(xnode.find("ifuns"))

    def initialize_compinfos(self, tnode: Optional[ET.Element]) -> None:
        if tnode:
            for x in tnode.findall("ci"):
                name = x.get("name")
                ixs = x.get("ixs")
                if name and ixs:
                    ids: List[int] = [int(n) for n in ixs.split(",")]
                    self._gcomptags.append(self.bcd.compinfo(ids[0]))

    def initialize_typeinfos(self, tnode: Optional[ET.Element]) -> None:
        if tnode:
            for x in tnode.findall("gt"):
                name = x.get("name")
                ixs = x.get("ixs")
                if name and ixs:
                    ids = [int(n) for n in ixs.split(",")]
                    self._gtypes.append(self.bcd.typ(ids[0]))

    def initialize_vardecls(self, tnode: Optional[ET.Element]) -> None:
        if tnode:
            for x in tnode.findall("vid"):
                name = x.get("name")
                ixs = x.get("ixs")
                if name and ixs:
                    ids = [int(n) for n in ixs.split(",")]
                    self._gvardecls.append(self.bcd.varinfo(ids[0]))

    def initialize_vardefs(self, tnode: Optional[ET.Element]) -> None:
        if tnode:
            for x in tnode.findall("vi"):
                name = x.get("name")
                ixs = x.get("ixs")
                if name and ixs:
                    ids = [int(n) for n in ixs.split(",")]
                    self._gvardefs.append(self.bcd.varinfo(ids[0]))

    def initialize_functions(self, tnode: Optional[ET.Element]) -> None:
        if tnode is not None:
            ifuns = tnode.get("ifuns")
            if ifuns:
                fnids = [int(n) for n in ifuns.split(",")]
                for fnid in fnids:
                    svinfo = self.bcd.varinfo(fnid)
                    xfundef = UF.get_bc_function_file_xnode(
                        self.app.path,
                        self.app.filename,
                        svinfo.vname)
                    self._functions[svinfo.vname] = BCFunctionDefinition(
                        self, svinfo.vname, xfundef)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("\n".join(str(t) for t in self.gtypes))
        lines.append("\n".join(str(c) for c in self.gcomptags))
        lines.append("\n".join(str(v) for v in self.gvardecls))
        for f in self.functions:
            print("  " + f)
        return "\n".join(lines)
