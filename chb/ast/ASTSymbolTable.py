# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022 Aarno Labs LLC
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
"""Symbol table with a one-to-one mapping from names to locations."""

from typing import Any, Dict, List, Mapping, Optional, Sequence, Set

from chb.ast.ASTIndexer import ASTIndexer
import chb.ast.ASTNode as AST
from chb.ast.ASTNodeDictionary import ASTNodeDictionary, get_key


class ASTSymbolTable:

    def __init__(self) -> None:
        self._table: Dict[str, AST.ASTVarInfo] = {}

    @property
    def table(self) -> Mapping[str, AST.ASTVarInfo]:
        return self._table

    @property
    def symbols(self) -> Sequence[AST.ASTVarInfo]:
        return list(self.table.values())

    def has_symbol(self, name: str) -> bool:
        return name in self.table

    def get_symbol(self, name: str) -> AST.ASTVarInfo:
        if name in self.table:
            return self.table[name]
        else:
            raise Exception("Symbol with name " + name + " not found")

    def add_symbol(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None) -> AST.ASTVarInfo:
        if vname in self.table:
            return self.table[vname]
        else:
            varinfo = AST.ASTVarInfo(
                vname,
                vtype=vtype,
                parameter=parameter,
                globaladdress=globaladdress,
                vdescr=vdescr)
            self._table[vname] = varinfo
            return varinfo

    def serialize(self, serializer: ASTIndexer) -> None:
        for (name, vinfo) in sorted(self.table.items()):
            vinfo.index(serializer)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Variables:")
        lines.append("-" * 80)
        for vinfo in self.table.values():
            lines.append(" - " + vinfo.vname)
        return "\n".join(lines)


class ASTGlobalSymbolTable(ASTSymbolTable):

    def __init__(self) -> None:
        ASTSymbolTable.__init__(self)
        self._symbolicaddrs: Dict[str, AST.ASTVarInfo] = {}
        self._referenced: Set[str] = set([])
        self._typesused: Set[int] = set([])
        self._compinfos: Dict[int, AST.ASTCompInfo] = {}

    @property
    def symbolic_addresses(self) -> Mapping[str, AST.ASTVarInfo]:
        return self._symbolicaddrs

    @property
    def compinfos(self) -> Mapping[int, AST.ASTCompInfo]:
        return self._compinfos

    def compinfo(self, ckey: int) -> AST.ASTCompInfo:
        if ckey in self.compinfos:
            return self.compinfos[ckey]
        else:
            raise Exception("No compinfo found for ckey: " + str(ckey))

    @property
    def referenced(self) -> Set[str]:
        """Return names of variables referenced."""

        return self._referenced

    def global_variable_name(self, gaddr: str) -> Optional[AST.ASTVarInfo]:
        if gaddr in self.symbolic_addresses:
            return self.symbolic_addresses[gaddr]
        else:
            return None

    def add_symbol(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None) -> AST.ASTVarInfo:
        if parameter is not None:
            raise Exception("Global variable cannot be a formal parameter")
        vinfo = ASTSymbolTable.add_symbol(
            self,
            vname,
            vtype=vtype,
            globaladdress=globaladdress,
            vdescr=vdescr)
        if globaladdress is not None and globaladdress > 0:
            self._symbolicaddrs[vinfo.vname] = vinfo
        return vinfo

    def add_varinfo(self, vinfo: AST.ASTVarInfo) -> None:
        if vinfo.vname not in self.symbolic_addresses:
            self._symbolicaddrs[vinfo.vname] = vinfo

    def add_compinfo(self, cinfo: AST.ASTCompInfo) -> None:
        if cinfo.ckey not in self.compinfos:
            self._compinfos[cinfo.ckey] = cinfo
        else:
            raise Exception(
                "Compinfo key "
                + str(cinfo.ckey)
                + " already exists: "
                + cinfo.cname)

    def has_compinfo(self, ckey: int) -> bool:
        return ckey in self.compinfos

    def serialize(self, indexer: ASTIndexer) -> None:
        ASTSymbolTable.serialize(self, indexer)
        for cinfo in self.compinfos.values():
            cinfo.index(indexer)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append(ASTSymbolTable.__str__(self))
        lines.append("\nStruct definitions")
        lines.append("-" * 80)
        for cinfo in self.compinfos.values():
            lines.append(str(cinfo.ckey).rjust(4) + "  " + cinfo.cname)
        return "\n".join(lines)


class ASTLocalSymbolTable(ASTSymbolTable):

    def __init__(
            self,
            globaltable: ASTGlobalSymbolTable) -> None:
        ASTSymbolTable.__init__(self)
        self._globaltable = globaltable
        self._formals: List[AST.ASTVarInfo] = []
        self._fprototype: Optional[AST.ASTVarInfo] = None

    @property
    def globaltable(self) -> ASTGlobalSymbolTable:
        return self._globaltable

    def add_global_symbol(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None) -> AST.ASTVarInfo:
        return self.globaltable.add_symbol(
            vname,
            vtype=vtype,
            globaladdress=globaladdress,
            vdescr=vdescr)

    @property
    def formals(self) -> Sequence[AST.ASTVarInfo]:
        return self._formals

    @property
    def function_prototype(self) -> Optional[AST.ASTVarInfo]:
        return self._fprototype

    @property
    def compinfos(self) -> Mapping[int, AST.ASTCompInfo]:
        return self.globaltable.compinfos

    def is_formal(self, vname: str) -> bool:
        return any([vinfo.vname == vname for vinfo in self.formals])

    def has_function_prototype(self) -> bool:
        return self.function_prototype is not None

    def set_function_prototype(self, vinfo: AST.ASTVarInfo) -> None:
        if vinfo.vtype is not None and vinfo.vtype.is_function:
            self._fprototype = vinfo
        else:
            raise Exception("Function prototype is not a function")

    def add_compinfo(self, cinfo: AST.ASTCompInfo) -> None:
        self.globaltable.add_compinfo(cinfo)
