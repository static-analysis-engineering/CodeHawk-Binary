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

from typing import (
    cast, Dict,  List, Mapping, Optional, Sequence, Set, Tuple, TYPE_CHECKING, Union)

from chb.app.ASTFormalVarInfo import ASTFormalVarInfo

import chb.app.ASTNode as AST

from chb.app.ASTVarInfo import ASTVarInfo

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.bctypes.BCFieldInfo import BCFieldInfo
    from chb.bctypes.BCFunctionDefinition import BCFunctionDefinition    
    from chb.bctypes.BCTyp import BCTyp, BCTypFun, BCTypComp, BCTypPtr, BCTypArray
    from chb.bctypes.BCVarInfo import BCVarInfo


nooffset = AST.ASTNoOffset()


class ASTSymbolTable:

    def __init__(self, callingconvention: str) -> None:
        self._callingconvention = callingconvention
        self._table: Dict[str, ASTVarInfo] = {}

    @property
    def callingconvention(self) -> str:
        """Return  a string that indicates where arguments are located.

        For now we use the architecture (that is, arm, mips, x86, powerpc)
        as an indicator of calling convention. Eventually we can add conventions
        like fastcall, cdecl, etc.
        """

        return self._callingconvention

    @property
    def table(self) -> Mapping[str, ASTVarInfo]:
        return self._table

    def serialize(self) -> Mapping[str, Dict[str, Union[int, str, List[str]]]]:
        result: Dict[str, Dict[str, Union[int, str, List[str]]]] = {}
        for (name, vinfo) in sorted(self.table.items()):
            result[name] = vinfo.serialize()
        return result

    def symbols(self) -> Sequence[ASTVarInfo]:
        return list(self.table.values())

    def global_symbols(self) -> Sequence[ASTVarInfo]:
        return [vinfo for vinfo in self.symbols() if vinfo.is_global]

    def has_symbol(self, name: str) -> bool:
        return name in self.table

    def get_symbol(self, name: str) -> ASTVarInfo:
        if name in self.table:
            return self.table[name]
        else:
            raise UF.CHBError("Symbol with name " + name + " not found")

    def is_variable_address(self, gaddr: int) -> Optional[str]:
        for (name, vinfo) in self.table.items():
            if vinfo.has_global_address():
                if vinfo.global_address == gaddr:
                    return name
        else:
            return None

    def is_struct_field_address(self, gaddr: int) -> bool:
        for gv in self.global_symbols():
            if gv.is_struct:
                compinfo = cast("BCTypComp", gv.vtype).compinfo
                gvaddr = gv.global_address
                if gvaddr:
                    gvextent = gvaddr + compinfo.byte_size()
                    return gaddr >= gvaddr and gaddr < gvextent
        else:
            return False

    def get_struct_field_address(self, gaddr: int) -> AST.ASTExpr:
        gvname: Optional[str] = None
        gvinfo: Optional[ASTVarInfo] = None

        for gv in self.global_symbols():
            if gv.is_struct:
                compinfo = cast("BCTypComp", gv.vtype).compinfo
                gvaddr = gv.global_address
                if gvaddr:
                    gvextent = gvaddr + compinfo.byte_size()
                    if gaddr >= gvaddr and gaddr < gvextent:
                        gvname = gv.vname
                        gvinfo = gv
                        break

        if gvname and gvinfo and gvinfo.global_address:
            compinfo = cast("BCTypComp", gvinfo.vtype).compinfo
            ioffset = gaddr - gvinfo.global_address
            fieldoffsets = compinfo.fieldoffsets()
            prevfinfo: Optional["BCFieldInfo"] = None
            prevoffset = -1
            if ioffset == 0:
                var = AST.ASTVariable(gvinfo)
                lval = AST.ASTLval(var, nooffset)
                return AST.ASTAddressOf(lval)

            for (foffset, finfo) in fieldoffsets:
                if ioffset == foffset:
                    var = AST.ASTVariable(gvinfo)
                    offset = AST.ASTFieldOffset(
                        finfo.fieldname, finfo.fieldtype, nooffset)
                    lval = AST.ASTLval(var, offset)
                    if finfo.fieldtype.is_array:
                        return AST.ASTLvalExpr(lval)
                    else:
                        return AST.ASTAddressOf(lval)

        raise Exception("Struct field not found at address " + hex(gaddr))
        
    def function_returntype(self, name: str) -> Optional["BCTyp"]:
        if self.has_symbol(name):
            vinfo = self.get_symbol(name)
            if vinfo.is_function:
                if vinfo.vtype:
                    vtype = cast("BCTypFun", vinfo.vtype)
                    return vtype.returntype
                else:
                    return None
            else:
                return None
        else:
            return None

    def add_symbol(
            self,
            vname: str,
            vtype: Optional["BCTyp"] = None,
            size: Optional[int] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            notes: Set[str] = set()) -> ASTVarInfo:
        if vname in self.table:
            return self.update_symbol(
                vname, vtype, size, parameter, globaladdress, notes=notes)
        else:
            varinfo = ASTVarInfo(
                vname,
                vtype=vtype,
                size=size,
                parameter=parameter,
                globaladdress=globaladdress,
                notes=notes)
            self._table[vname] = varinfo
            return varinfo

    def update_symbol(
            self,
            vname: str,
            vtype: Optional["BCTyp"],
            size: Optional[int],
            parameter: Optional[int],
            globaladdress: Optional[int],
            notes: Set[str]) -> ASTVarInfo:
        vinfo = self.table[vname]
        newtype: Optional["BCTyp"]
        newconflicts: List["BCTyp"]

        # set type to most precise (not-conflicting), or record conflict
        if vtype and vinfo.vtype:
            if vtype.is_leq(vinfo.vtype):
                newtype = vtype
            elif vinfo.vtype.is_leq(vtype):
                newtype = vinfo.vtype
            else:
                newtype = None
                newconflicts = [vinfo.vtype, vtype]
        elif len(vinfo.conflicting_types) > 0:
            for t in vinfo.conflicting_types:
                if vtype and vtype.is_leq(t):
                    newconflicts.append(vtype)
                else:
                    newconflicts.append(t)
        elif vtype:
            newtype = vtype
        else:
            newtype = vinfo.vtype

        # set size to most precise version or remove
        if size and vinfo.size:
            if size == vinfo.size:
                newsize: Optional[int] = size
            else:
                newsize = None
        elif size:
            newsize = size
        else:
            newsize = vinfo.size

        # set global address to most precise version or remove
        if globaladdress and vinfo.global_address:
            if globaladdress == vinfo.global_address:
                newglobaladdress: Optional[int] = globaladdress
            else:
                newglobaladdress = None
        elif globaladdress:
            newglobaladdress = globaladdress
        else:
            newglobaladdress = vinfo.global_address

        parameter = vinfo.parameter if vinfo.is_parameter else None
        newnotes = vinfo.notes | notes

        # create new varinfo
        newvinfo = ASTVarInfo(
            vname,
            vtype=newtype,
            size=newsize,
            parameter=parameter,
            globaladdress=newglobaladdress,
            notes=newnotes)
        self._table[vname] = newvinfo
        return newvinfo

    '''
    def get_global_denotation(
            self,
            gvinfo: AST.ASTVarInfo,
            gaddr: str,
            offset: AST.ASTOffset) -> Tuple[AST.ASTVariable, AST.ASTOffset]:
        addr = int(gaddr, 16)
        if gvinfo.is_struct:
            compinfo = (cast("BCTypComp", gvinfo.vtype)).compinfo
            ioffset = addr - gvinfo.global_address
            fieldoffsets = compinfo.fieldoffsets()
            prevfinfo: Optional["BCFieldInfo"] = None
            prevoffset = -1
            for (foffset, finfo) in fieldoffsets:
                if ioffset == foffset:
                    id = self.new_id()
                    var = AST.ASTVariable(id, gvinfo)
                    if finfo.fieldtype.is_array:
                        offset = self.mk_scalar_index_offset(0, offset)
                    offset = self.mk_field_offset(
                        finfo.fieldname, finfo.fieldtype, offset)
                    return (var, offset)
                elif ioffset > foffset:
                    prevfinfo = finfo
                    prevoffset = foffset
                else:
                    if prevfinfo is None:
                        raise Exception("Offset mismatch")
                    if prevfinfo.fieldtype.is_array:
                        ftype = cast("BCTypArray", prevfinfo.fieldtype)
                        eltsize = ftype.tgttyp.byte_size()
                        aoffset = ioffset - prevoffset
                        if aoffset % eltsize == 0:
                            aindex = aoffset // eltsize
                            offset = self.mk_scalar_index_offset(aindex, offset)
                        else:
                            raise Exception("Offset mismatch")
                        id = self.new_id()
                        var = AST.ASTVariable(id, gvinfo)
                        offset = self.mk_field_offset(
                            prevfinfo.fieldname, prevfinfo.fieldtype, offset)
                        return (var, offset)
                    else:
                        name = "gv_" + gaddr
                        return (self.mk_global_variable(
                            name, globaladdress=int(gaddr, 16)), offset)
            else:
                name = "gv_" + gaddr
                return (self.mk_global_variable(
                    name, globaladdress=int(gaddr, 16)), offset)

        else:
            id = self.new_id()
            var = AST.ASTVariable(id, gvinfo)
            return (var, offset)
    '''

    def __str__(self) -> str:
        lines: List[str] = []
        for vinfo in self.table.values():
            if vinfo.vtype is not None:
                lines.append(str(vinfo.vtype) + " " + vinfo.vname)
            else:
                lines.append("? " + vinfo.vname)
        return "\n".join(lines)

            
class ASTGlobalSymbolTable(ASTSymbolTable):

    def __init__(self, callingconvention: str) -> None:
        ASTSymbolTable.__init__(self, callingconvention)
        self._symbolicaddrs: Dict[str, ASTVarInfo] = {}
        self._referenced: Set[str] = set([])
        self._typesused: Set[int] = set([])

    @property
    def symbolicaddrs(self) -> Dict[str, ASTVarInfo]:
        return self._symbolicaddrs

    @property
    def referenced(self) -> Set[str]:
        return self._referenced

    @property
    def types_used(self) -> Set[int]:
        return self._typesused

    def add_referenced(self, name: str) -> None:
        self._referenced.add(name)

    def add_type_used(self, t: "BCTyp") -> None:
        if t.is_void or t.is_integer or t.is_float:
            self._typesused.add(t.index)
        elif t.is_pointer:
            t = cast("BCTypPtr", t)
            self.add_type_used(t.tgttyp)
        elif t.is_array:
            t = cast("BCTypArray", t)
            self.add_type_used(t.tgttyp)
        elif t.is_function:
            t = cast("BCTypFun", t)
            self.add_type_used(t.returntype)
            if t.argtypes is not None:
                for a in t.argtypes.argtypes:
                    self.add_type_used(a)
        elif t.is_struct:
            self._typesused.add(t.index)
            t = cast("BCTypComp", t)
            compinfo = t.compinfo
            for field in compinfo.fieldinfos:
                self.add_type_used(field.fieldtype)
        else:
            self._typesused.add(t.index)

    def add_global_symbol(
            self,
            vname: str,
            vtype: Optional["BCTyp"] = None,
            globaladdress: Optional[int] = None,
            size: Optional[int] = None) -> None:
        gvar = ASTSymbolTable.add_symbol(
            self, vname, vtype=vtype, globaladdress=globaladdress, size=size)
        if globaladdress is not None:        
            self._symbolicaddrs[hex(globaladdress)] = gvar

    def global_variable_name(self, gaddr: str) -> Optional[ASTVarInfo]:
        if gaddr in self.symbolicaddrs:
            return self.symbolicaddrs[gaddr]
        else:
            return None

    def serialize(self) -> Mapping[str, Dict[str, Union[int, str, List[str]]]]:
        result: Dict[str, Dict[str, Union[int, str, List[str]]]] = {}
        for (name, vinfo) in sorted(self.table.items()):
            if name in self.referenced:
                result[name] = vinfo.serialize()
        return result

    def __str__(self) -> str:
        lines: List[str] = []
        for vinfo in sorted(self.table.values(), key=lambda v:v.vname):
            if vinfo.vname in self.referenced:
                gaddr = vinfo.global_address
                if gaddr:
                    pgaddr = " // " + hex(gaddr)
                else:
                    pgaddr = ""
                if vinfo.vtype is not None:
                    if vinfo.vtype.is_function:
                        t = cast("BCTypFun", vinfo.vtype)
                        lines.append(
                            str(t.returntype)
                            + " "
                            + vinfo.vname
                            + str(t.argtypes)
                            + pgaddr)
                    else:
                        lines.append(
                            str(vinfo.vtype) + " " + vinfo.vname + pgaddr)
                else:
                    lines.append("? " + vinfo.vname + pgaddr)

        return "\n".join(lines)


class ASTLocalSymbolTable(ASTSymbolTable):
    def __init__(
            self,
            globaltable: ASTGlobalSymbolTable,
            callingconvention: str) -> None:
        ASTSymbolTable.__init__(self, callingconvention)
        self._globaltable: ASTGlobalSymbolTable = globaltable
        self._formals: List[ASTFormalVarInfo] = []
        self._fprototype: Optional["BCVarInfo"] = None
        self._functiondef: Optional["BCFunctionDefinition"] = None
        self._diagnostics: List[str] = []

    @property
    def globaltable(self) -> ASTGlobalSymbolTable:
        return self._globaltable

    @property
    def diagnostics(self) -> List[str]:
        return self._diagnostics

    def add_diagnostic(self, msg: str) -> None:
        self._diagnostics.append(msg)

    @property
    def formals(self) -> List[ASTFormalVarInfo]:
        return self._formals

    def is_formal(self, name: str) -> bool:
        return name in [f.vname for f in self.formals]

    def has_functiondef(self) -> bool:
        return self._functiondef is not None

    @property
    def functiondef(self) -> "BCFunctionDefinition":
        if self._functiondef:
            return self._functiondef
        else:
            raise Exception("Function has no functiondef")

    def has_function_prototype(self) -> bool:
        return self._fprototype is not None        

    @property
    def function_prototype(self) -> "BCVarInfo":
        if self._fprototype is not None:
            return self._fprototype
        else:
            raise Exception("Function has no known prototype")

    def set_functiondef(self, d: "BCFunctionDefinition") -> None:
        self._functiondef = d    
        
    def set_function_prototype(self, p: "BCVarInfo") -> None:
        self._fprototype = p
        ftype = cast("BCTypFun", p.vtype)
        if ftype.argtypes:
            nextindex = 0
            for (argindex, arg) in enumerate(ftype.argtypes.funargs):
                nextindex = self.add_formal(
                    arg.name, arg.typ, argindex, nextindex)

    def global_variable_name(self, gaddr: str) -> Optional[ASTVarInfo]:
        return self.globaltable.global_variable_name(gaddr)

    def get_formal_locindices(
            self, argindex: int) -> Tuple[ASTFormalVarInfo, List[int]]:
        """Return the indices of the arg location(s) for argindex.

        There may be more than one location in case of a packed array.
        """

        for formal in reversed(self.formals):
            if argindex >= formal.argindex:
                if (argindex - formal.argindex) < formal.numargs:
                    return (formal, formal.arglocs_for_argindex(argindex))
                else:
                    raise Exception(
                        "get_formal_locindex: "
                        + str(argindex)
                        + " is too large. Formals:  "
                        + ", ".join(str(f) for f in self.formals))

        else:
            raise Exception("No formal found for argindex: " + str(argindex))

    def function_argument(self, index: int) -> List[AST.ASTLval]:
        """Return the argument(s) with the given index (zero-based).

        There may be more than one argument, in case of a packed array.
        """

        if len(self.formals) > 0:
            (formal, locindices) = self.get_formal_locindices(index)
            regvar = AST.ASTVariable(formal)
            lvals: List[AST.ASTLval] = []
            for locindex in locindices:
                (loc, offset, size) = formal.argloc(locindex)
                lvals.append(AST.ASTLval(regvar, offset))
            return lvals
        else:
            if self.has_function_prototype():
                self.add_diagnostic(
                    str(self.function_prototype)
                    + " has no parameters")
            else:
                self.add_diagnostic(
                    "No function prototype present to extract parameters")
            return []

    def add_symbol(
            self,
            vname: str,
            vtype: Optional["BCTyp"] = None,
            size: Optional[int] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            notes: Set[str] = set()) -> ASTVarInfo:

        if self.has_symbol(vname):
            varinfo = self.update_symbol(
                vname, vtype, size, parameter, globaladdress, notes=notes)
        elif self.globaltable.has_symbol(vname):
            self.globaltable.add_referenced(vname)
            varinfo = self.globaltable.update_symbol(
                vname, vtype, size, parameter, globaladdress, notes=notes)
        elif globaladdress is not None:
            self.globaltable.add_referenced(vname)
            varinfo = self.globaltable.add_symbol(
                vname,
                vtype=vtype,
                size=size,
                parameter=parameter,
                globaladdress=globaladdress,
                notes=notes)
        else:
            varinfo = ASTSymbolTable.add_symbol(
                self,
                vname,
                vtype=vtype,
                size=size,
                parameter=parameter,
                globaladdress=globaladdress,
                notes=notes)
        if varinfo.vtype is not None:
            self.globaltable.add_type_used(varinfo.vtype)
        return varinfo        

    def add_formal(
            self,
            vname: str,
            vtype: "BCTyp",
            parameter: int,
            nextindex: int) -> int:
        """Return the next starting index for the argument in the binary."""

        formal = ASTFormalVarInfo(vname, parameter, nextindex, vtype=vtype)
        nextindex = formal.initialize(self.callingconvention)
        self.add_symbol(vname, vtype=vtype, parameter=parameter)
        self._formals.append(formal)
        return nextindex
