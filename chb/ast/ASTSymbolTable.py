# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2024  Aarno Labs LLC
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

from typing import Any, cast, Dict, List, Mapping, Optional, Sequence, Set

from chb.ast.ASTByteSizeCalculator import (
    ASTByteSizeCalculator, ASTByteSizeCalculationException)
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
            llref: bool = False,
            vdescr: Optional[str] = None) -> AST.ASTVarInfo:

        # Variables with type void are illegal in C. We switch
        # the type to iuchar as a sensible default.
        if vtype is not None and vtype.is_void:
            vtype = AST.ASTTypInt("iuchar")

        if vname in self.table:
            varinfo = self.table[vname]
            if parameter is not None or globaladdress is not None:
                return varinfo

            if varinfo.vtype is None and vtype is not None:
                # Add a type to the existing ASTVarInfo. Note that we don't
                # switch a valid existing type, that seems something the caller
                # should take care of if they need to (or add a cast).
                varinfo.vtype = vtype

            # Check if we should update the description
            vinfodescr: Optional[str] = None
            if vdescr is not None:
                if varinfo.vdescr is not None:
                    vinfodescr = vdescr + ";" + varinfo.vdescr
                else:
                    vinfodescr = vdescr
            else:
                if varinfo.vdescr is not None:
                    vinfodescr = varinfo.vdescr
                else:
                    vinfodescr = None
            if vinfodescr:
                varinfo.vdescr = vinfodescr

            return varinfo
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
            lines.append(" - " + str(vinfo.vtype) + " " + vinfo.vname)
        return "\n".join(lines)


class ASTGlobalSymbolTable(ASTSymbolTable):

    def __init__(self) -> None:
        ASTSymbolTable.__init__(self)
        self._symbolicaddrs: Dict[str, AST.ASTVarInfo] = {}
        self._symbolicnames: Dict[str, AST.ASTVarInfo] = {}
        self._referenced: Set[str] = set([])
        self._typesused: Set[int] = set([])
        self._compinfos: Dict[int, AST.ASTCompInfo] = {}
        self._enuminfos: Dict[str, AST.ASTEnumInfo] = {}
        self._typedefs: Dict[str, AST.ASTTyp] = {}
        self._lval_counter: int = 1
        self._expr_counter: int = 1

    @property
    def symbolic_addresses(self) -> Mapping[str, AST.ASTVarInfo]:
        """Return a mapping from global addresses to varinfos."""

        return self._symbolicaddrs

    @property
    def symbolic_names(self) -> Mapping[str, AST.ASTVarInfo]:
        """Return a mapping from global variable names to varinfos."""

        return self._symbolicnames

    @property
    def compinfos(self) -> Mapping[int, AST.ASTCompInfo]:
        return self._compinfos

    @property
    def enuminfos(self) -> Mapping[str, AST.ASTEnumInfo]:
        return self._enuminfos

    @property
    def typedefs(self) -> Mapping[str, AST.ASTTyp]:
        return self._typedefs

    def resolve_typedef(self, name: str) -> AST.ASTTyp:
        if name in self.typedefs:
            tdef = self.typedefs[name]
            if tdef.is_typedef:
                tdef = cast(AST.ASTTypNamed, tdef)
                return self.resolve_typedef(tdef.typname)
            else:
                return tdef
        else:
            raise Exception("Unknown typedef name: " + str(name))

    def add_typedef(self, typedef: AST.ASTTypNamed) -> None:
        self._typedefs[typedef.typname] = typedef.typdef

    def new_lvalid(self) -> int:
        """Return a new lval id for lvalues."""

        lvalid = self._lval_counter
        self._lval_counter += 1
        return lvalid

    def get_lvalid(self, lvalid: Optional[int]) -> int:
        return self.new_lvalid() if lvalid is None else lvalid

    def new_exprid(self) -> int:
        """Return a new expr id for expressions."""

        exprid = self._expr_counter
        self._expr_counter += 1
        return exprid

    def get_exprid(self, exprid: Optional[int]) -> int:
        return self.new_exprid() if exprid is None else exprid

    def compinfo(self, ckey: int) -> AST.ASTCompInfo:
        if ckey in self.compinfos:
            return self.compinfos[ckey]
        else:
            raise Exception("No compinfo found for ckey: " + str(ckey))

    def enuminfo(self, enumname: str) -> AST.ASTEnumInfo:
        if enumname in self.enuminfos:
            return self.enuminfos[enumname]
        else:
            raise Exception("No enuminfo found for name: " + enumname)

    @property
    def referenced(self) -> Set[str]:
        """Return names of variables referenced."""

        return self._referenced

    def global_variable_name(self, gaddr: str) -> Optional[AST.ASTVarInfo]:
        if gaddr in self.symbolic_addresses:
            return self.symbolic_addresses[gaddr]
        else:
            return None

    def in_global_variable(
            self,
            gaddr: str,
            size_calculator: ASTByteSizeCalculator) -> Optional[AST.ASTVarInfo]:
        """Return a variable that includes the global address within its extent."""

        if gaddr in self.symbolic_addresses:
            return self.symbolic_addresses[gaddr]
        else:
            igaddr = int(gaddr, 16)
            for (a, gvinfo) in self.symbolic_addresses.items():
                if int(a, 16) < igaddr:
                    if gvinfo.vtype is not None:
                        try:
                            if int(a, 16) + gvinfo.vtype.index(size_calculator) > igaddr:
                                return gvinfo
                        except ASTByteSizeCalculationException as e:
                            print("Unable to determine size of " + str(gvinfo))

        return None

    def add_symbol(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            llref: bool = False,
            vdescr: Optional[str] = None) -> AST.ASTVarInfo:
        if parameter is not None:
            raise Exception("Global variable cannot be a formal parameter")
        vinfo = ASTSymbolTable.add_symbol(
            self,
            vname,
            vtype=vtype,
            globaladdress=globaladdress,
            vdescr=vdescr)
        if globaladdress is not None:
            self._symbolicnames[vinfo.vname] = vinfo
            if globaladdress > 0:
                self._symbolicaddrs[hex(globaladdress)] = vinfo
            if not llref:
                self._referenced.add(vinfo.vname)
        return vinfo

    def add_compinfo(self, cinfo: AST.ASTCompInfo) -> None:
        if cinfo.compkey not in self.compinfos:
            self._compinfos[cinfo.compkey] = cinfo
        else:
            raise Exception(
                "Compinfo key "
                + str(cinfo.compkey)
                + " already exists: "
                + cinfo.compname)

    def add_enuminfo(self, einfo: AST.ASTEnumInfo) -> None:
        if einfo.enumname not in self.enuminfos:
            self._enuminfos[einfo.enumname] = einfo
        else:
            raise Exception(
                "Enuminfo with name " + einfo.enumname + " already exists")

    def has_compinfo(self, ckey: int) -> bool:
        return ckey in self.compinfos

    def has_enuminfo(self, enumname: str) -> bool:
        return enumname in self.enuminfos

    def serialize(self, indexer: ASTIndexer) -> None:
        ASTSymbolTable.serialize(self, indexer)
        for cinfo in self.compinfos.values():
            cinfo.index(indexer)

        for einfo in self.enuminfos.values():
            einfo.index(indexer)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append(ASTSymbolTable.__str__(self))
        lines.append("\nStruct definitions")
        lines.append("-" * 80)
        for cinfo in self.compinfos.values():
            lines.append(str(cinfo.compkey).rjust(4) + "  " + cinfo.compname)
        lines.append("\nEnum definitions")
        lines.append("-" * 80)
        for einfo in self.enuminfos.values():
            lines.append(einfo.enumname)
        lines.append("\nType definitions")
        lines.append("-" * 80)
        for name in sorted(self.typedefs):
            lines.append(name + ": " + str(self.typedefs[name]))
        return "\n".join(lines)


class ASTLocalSymbolTable(ASTSymbolTable):

    def __init__(
            self,
            globaltable: ASTGlobalSymbolTable) -> None:
        ASTSymbolTable.__init__(self)
        self._globaltable = globaltable
        self._fprototype: Optional[AST.ASTVarInfo] = None

    @property
    def globaltable(self) -> ASTGlobalSymbolTable:
        return self._globaltable

    def add_global_symbol(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            globaladdress: Optional[int] = None,
            llref: bool = False,
            vdescr: Optional[str] = None) -> AST.ASTVarInfo:
        return self.globaltable.add_symbol(
            vname,
            vtype=vtype,
            globaladdress=globaladdress,
            llref=llref,
            vdescr=vdescr)

    @property
    def formals(self) -> Sequence[AST.ASTVarInfo]:
        result: List[AST.ASTVarInfo] = []
        for vinfo in self.symbols:
            if vinfo.parameter is not None:
                result.append(vinfo)
        return result

    @property
    def function_prototype(self) -> Optional[AST.ASTVarInfo]:
        return self._fprototype

    @property
    def compinfos(self) -> Mapping[int, AST.ASTCompInfo]:
        return self.globaltable.compinfos

    @property
    def enuminfos(self) -> Mapping[str, AST.ASTEnumInfo]:
        return self.globaltable.enuminfos

    def is_formal(self, vname: str) -> bool:
        return any([vinfo.vname == vname for vinfo in self.formals])

    def has_function_prototype(self) -> bool:
        return self.function_prototype is not None

    def set_function_prototype(self, vinfo: AST.ASTVarInfo) -> None:
        if vinfo.vtype is not None and vinfo.vtype.is_function:
            self._fprototype = vinfo
        else:
            raise Exception("Function prototype is not a function")

    def serialize_function_prototype(self, serializer: ASTIndexer) -> int:
        if self.function_prototype is not None:
            return self.function_prototype.index(serializer)
        else:
            return -1

    def has_compinfo(self, ckey: int) -> bool:
        return self.globaltable.has_compinfo(ckey)

    def compinfo(self, ckey: int) -> AST.ASTCompInfo:
        return self.globaltable.compinfo(ckey)

    def add_compinfo(self, cinfo: AST.ASTCompInfo) -> None:
        self.globaltable.add_compinfo(cinfo)

    def has_enuminfo(self, enumname: str) -> bool:
        return self.globaltable.has_enuminfo(enumname)

    def enuminfo(self, enumname: str) -> AST.ASTEnumInfo:
        return self.globaltable.enuminfo(enumname)

    def add_enuminfo(self, einfo: AST.ASTEnumInfo) -> None:
        self.globaltable.add_enuminfo(einfo)
