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
"""Construction of abstract syntax tree."""

import json

from typing import (
    Any,
    Callable,
    cast,
    Dict,
    List,
    Mapping,
    NewType,
    Optional,
    Sequence,
    Tuple,
    TYPE_CHECKING,
    Union)

import chb.app.ASTNode as AST
import chb.app.ASTUtil as AU

if TYPE_CHECKING:
    from chb.bctypes.BCFieldInfo import BCFieldInfo
    from chb.bctypes.BCFunArgs import BCFunArg
    from chb.bctypes.BCFunctionDefinition import BCFunctionDefinition
    from chb.bctypes.BCTyp import BCTyp, BCTypFun, BCTypComp, BCTypArray, BCTypPtr
    from chb.bctypes.BCVarInfo import BCVarInfo


ASTSpanRecord = NewType(
    "ASTSpanRecord", Dict[str, Union[int, List[Dict[str, Union[str, int]]]]])

"""fname -> registers/stack -> name/offset -> [span/altname -> (low, high), name]."""
VariableNamesRec = NewType(
    "VariableNamesRec",
    Dict[str, Dict[str, Dict[str, List[Dict[str, Union[Tuple[str, str], str]]]]]])


ignoredvariable = AST.ASTVarInfo(-1, "ignored", None, None, None, None)
nooffset = AST.ASTNoOffset(-1)


class VariableNames:

    def __init__(self, namerecords: VariableNamesRec) -> None:
        self._namerecords = namerecords

    @property
    def namerecords(self) -> VariableNamesRec:
        return self._namerecords

    def has_register_variable(self, fname: str, v: str) -> bool:
        return (
            fname in self.namerecords
            and "registers" in self.namerecords[fname]
            and v in self.namerecords[fname]["registers"])

    def has_stack_variable(self, fname: str, offset: int) -> bool:
        return (
            fname in self.namerecords
            and "stack" in self.namerecords[fname]
            and str(offset) in self.namerecords[fname]["stack"])

    def has_other_variable(self, fname: str, name: str) -> bool:
        return (
            fname in self.namerecords
            and "other" in self.namerecords[fname]
            and name in self.namerecords[fname]["other"])

    def register_variable(self, fname: str, v: str, addr: str) -> Optional[str]:
        if self.has_register_variable(fname, v):
            vrec = self.namerecords[fname]["registers"][v]
            addri = int(addr, 16)
            for span in vrec:
                if "span" in span:
                    vlow = int(span["span"][0], 16)
                    vhigh = int(span["span"][1], 16)
                    if vlow <= addri and addri <= vhigh:
                        return cast(str, span["altname"])
                else:
                    # variable name applies throughout the function
                    return cast(str, span["altname"])
            else:
                return None
        else:
            return None

    def stack_variable(self, fname: str, offset: int, addr: str) -> Optional[str]:
        if self.has_stack_variable(fname, offset):
            vrec = self.namerecords[fname]["stack"][str(offset)]
            addri = int(addr, 16)
            for span in vrec:
                if "span" in span:
                    vlow = int(span["span"][0], 16)
                    vhigh = int(span["span"][1], 16)
                    if vlow <= addri and addri <= vhigh:
                        return cast(str, span["altname"])
                else:
                    # variable name applies throughout the function
                    return cast(str, span["altname"])
            else:
                return None
        else:
            return None

    def other_variable(self, fname: str, name: str) -> Optional[str]:
        if self.has_other_variable(fname, name):
            vrec = self.namerecords[fname]["other"][name]
            return cast(str, vrec[0]["altname"])
        else:
            return None


class AbstractSyntaxTree:

    def __init__(
            self,
            faddr: str,
            fname: str,
            variablenames: VariableNamesRec = cast(VariableNamesRec, {}),
            symbolicaddrs: Dict[str, str] = {},
            ignore_return_value: List[str] = [],
            callingconvention: str = "arm") -> None:
        self._faddr = faddr
        self._fname = fname  # same as faddr if no name provided
        self._counter = 0
        self._vcounter = 0
        self._tmpcounter = 0
        self._spans: List[ASTSpanRecord] = []
        self._variablenames = VariableNames(variablenames)
        self._ignore_return_value = ignore_return_value
        self._symbolicaddrs = symbolicaddrs
        self._callingconvention = callingconvention
        self._currentaddr: Optional[str] = None
        self._symboltable: Dict[Tuple[str, str], AST.ASTVarInfo] = {}
        self._symboltable[("ignored", "__none__")] = ignoredvariable
        self._unsupported: Dict[str, List[str]] = {}
        self._fprototype: Optional["BCVarInfo"] = None
        self._functiondef: Optional["BCFunctionDefinition"] = None
        self._formals: List[AST.ASTFormalVarInfo] = []

    @property
    def fname(self) -> str:
        return self._fname

    @property
    def spans(self) -> List[ASTSpanRecord]:
        return self._spans

    @property
    def symboltable(self) -> Dict[Tuple[str, str], AST.ASTVarInfo]:
        return self._symboltable

    @property
    def symbolicaddrs(self) -> Dict[str, str]:
        return self._symbolicaddrs

    @property
    def formals(self) -> List[AST.ASTFormalVarInfo]:
        return self._formals

    @property
    def callingconvention(self) -> str:
        """Return  a string that indicates where arguments are located.

        For now we use the architecture (that is, arm, mips, x86, powerpc)
        as an indicator of calling convention. Eventually we can add conventions
        like fastcall, cdecl, etc.
        """
        return self._callingconvention

    def ignore_return_value(self, name: str) -> bool:
        return name in self._ignore_return_value

    def global_variable_name(self, gaddr: str) -> Optional[str]:
        if gaddr in self.symbolicaddrs:
            return self.symbolicaddrs[gaddr]
        else:
            return None

    def storage_records(self) -> List[Dict[str, str]]:
        return AU.storage_records(list(self.symboltable.values()))

    def global_symbols(self) -> List[AST.ASTVarInfo]:
        return [vinfo for vinfo in self.symboltable.values() if vinfo.is_global]

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

    def function_prototype(self) -> "BCVarInfo":
        if self._fprototype is not None:
            return self._fprototype
        else:
            raise Exception("Function has no known prototype")

    def get_formal_locindex(self, argindex: int) -> Tuple[AST.ASTFormalVarInfo, int]:
        for formal in reversed(self.formals):
            if argindex >= formal.argindex:
                if (argindex - formal.argindex) < formal.numargs:
                    return (formal, argindex - formal.argindex)
                else:
                    raise Exception(
                        "get_formal_locindex: "
                        + str(argindex)
                        + " is too large. Formals:  "
                        + ", ".join(str(f) for f in self.formals))

        else:
            raise Exception("No formal found for argindex: " + str(argindex))

    def function_argument(self, index: int) -> Optional[AST.ASTLval]:
        """Return the argument with the given index (zero-based)."""

        if len(self.formals) > 0:
            (formal, locindex) = self.get_formal_locindex(index)
            id = self.new_id()
            regvar = AST.ASTVariable(id, formal)
            id = self.new_id()
            (loc, offset, start) = formal.argloc(locindex)
            return AST.ASTLval(id, regvar, offset)
        else:
            return None

    def has_symbol(self, name: str, altname: Optional[str] = None) -> bool:
        index = (name, altname) if altname else (name, "__none__")
        return index in self.symboltable

    def symbol(self, name: str, altname: Optional[str] = None) -> AST.ASTVarInfo:
        index = (name, altname) if altname else (name, "__none__")
        if self.has_symbol(name, altname=altname):
            return self.symboltable[index]
        else:
            print("Internal error: symbol not found: " + str(index))
            exit(1)

    def add_symbol(
            self,
            vname: str,
            vtype: Optional["BCTyp"],
            altname: Optional[str],
            parameter: Optional[int],
            globaladdress: Optional[int],
            arrayindex: Optional[int] = None) -> None:
        id = self.new_id()
        varinfo = AST.ASTVarInfo(
            id,
            vname,
            vtype,
            altname,
            parameter,
            globaladdress,
            arrayindex=arrayindex)
        index = (vname, altname) if altname else (vname, "__none__")
        self._symboltable[index] = varinfo

    def add_formal(
            self,
            vname: str,
            vtype: "BCTyp",
            parameter: int,
            nextindex: int) -> int:
        """Return the next starting index for the argument in the binary."""

        id = self.new_id()
        formal = AST.ASTFormalVarInfo(id, vname, vtype, parameter, nextindex)
        nextindex = formal.initialize(self.new_id, self.callingconvention)
        self._symboltable[(vname, "__none__")] = formal
        self._formals.append(formal)
        return nextindex

    def get_symbol(
            self,
            name: str,
            vtype: Optional["BCTyp"],
            altname: Optional[str],
            parameter: Optional[int],
            globaladdress: Optional[int],
            arrayindex: Optional[int] = None) -> AST.ASTVarInfo:
        if not self.has_symbol(name, altname):
            self.add_symbol(
                name,
                vtype,
                altname,
                parameter,
                globaladdress,
                arrayindex=arrayindex)
        return self.symbol(name, altname=altname)

    def serialize_symboltable(self) -> List[AST.ASTNodeRecord]:
        result: List[AST.ASTNodeRecord] = []
        for vinfo in self.symboltable.values():
            result.extend(vinfo.serialize())
        return result

    def new_id(self) -> int:
        id = self._counter
        self._counter += 1
        return id

    def new_tmp_id(self) -> int:
        tmpid = self._tmpcounter
        self._tmpcounter += 1
        return tmpid

    def add_span(self, span: ASTSpanRecord) -> None:
        self._spans.append(span)

    def add_instruction_span(self, id: int, base: str, bytestring: str) -> None:
        span: Dict[str, Union[str, int]] = {}
        span["base_va"] = base
        span["size"] = len(bytestring) // 2
        spanrec: Dict[str, Any] = {}
        spanrec["id"] = id
        spanrec["spans"] = [span]
        self.add_span(cast(ASTSpanRecord, spanrec))

    def add_instruction_unsupported(self, mnem: str, instr: str) -> None:
        self._unsupported.setdefault(mnem, [])
        self._unsupported[mnem].append(instr)

    @property
    def unsupported_instructions(self) -> Dict[str, List[str]]:
        return self._unsupported

    def set_current_addr(self, addr: str) -> None:
        """Set address of current instruction.

        Only used if incorporating user-provided alternate variable names,
        otherwise unused.
        """
        self._currentaddr = addr

    def register_variable_name(self, r: str) -> Optional[str]:
        """Retrieve the alternate name of a register at a given address.

        Only used if incorporating user-provided alternate variable names,
        otherwise not relevant.
        """
        if self._currentaddr:
            return self._variablenames.register_variable(
                self.fname, r, self._currentaddr)
        else:
            return None

    def stack_variable_name(self, offset: int) -> Optional[str]:
        """Retrieve the altnernate name of a stack variable given offset."""

        if self._currentaddr:
            return self._variablenames.stack_variable(
                self.fname, offset, self._currentaddr)
        else:
            return None

    def other_variable_name(self, name: str) -> Optional[str]:
        return self._variablenames.other_variable(self.fname, name)

    def function_returntype(self, name: str) -> Optional["BCTyp"]:
        if self.has_symbol(name):
            vinfo = self.symbol(name)
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

    def mk_block(self, stmts: List[AST.ASTStmt]) -> AST.ASTBlock:
        id = self.new_id()
        return AST.ASTBlock(id, stmts)

    def mk_return_stmt(self, expr: Optional[AST.ASTExpr]) -> AST.ASTReturn:
        id = self.new_id()
        return AST.ASTReturn(id, expr)

    def mk_branch(
            self,
            condition: Optional[AST.ASTExpr],
            ifbranch: AST.ASTStmt,
            elsebranch: AST.ASTStmt,
            relative_offset: int) -> AST.ASTStmt:
        id = self.new_id()
        if condition is None:
            # create a new unknown (unitialized) variable
            condvar = self.mk_temp_lval()
            condition = self.mk_lval_expr(condvar)
        return AST.ASTBranch(id, condition, ifbranch, elsebranch, relative_offset)

    def mk_instr_sequence(self, instrs: List[AST.ASTInstruction]) -> AST.ASTInstrSequence:
        id = self.new_id()
        return AST.ASTInstrSequence(id, instrs)

    def mk_variable(self, name: str) -> AST.ASTVariable:
        id = self.new_id()
        altname = self.other_variable_name(name)
        varinfo = self.get_symbol(name, None, altname, None, None)
        return AST.ASTVariable(id, varinfo)

    def mk_global_variable(
            self,
            name: str,
            vtype: Optional["BCTyp"] = None,
            globaladdress: Optional[int] = None) -> AST.ASTVariable:
        id = self.new_id()
        varinfo = self.get_symbol(name, vtype, None, None, globaladdress)
        return AST.ASTVariable(id, varinfo)

    def mk_global_variable_lval(
            self,
            name: str,
            vtype: Optional["BCTyp"] = None,
            globaladdress: Optional[int] = None) -> AST.ASTLval:
        id = self.new_id()
        var = self.mk_global_variable(name, vtype, globaladdress)
        return AST.ASTLval(id, var, nooffset)

    def mk_global_variable_expr(
            self,
            name: str,
            vtype: Optional["BCTyp"] = None,
            globaladdress: Optional[int] = None) -> AST.ASTExpr:
        id = self.new_id()
        lval = self.mk_global_variable_lval(name, vtype, globaladdress)
        return AST.ASTLvalExpr(id, lval)

    def mk_returnval_variable(
            self,
            iaddr: str,
            vtype: Optional["BCTyp"]) -> AST.ASTVariable:
        id = self.new_id()
        name = "rtn_" + iaddr
        altname = self.other_variable_name(name)
        if (
                altname
                and self.has_functiondef()
                and self.functiondef.has_localvar(altname)):
            localvinfo = self.functiondef.localvar(altname)
            varinfo = self.get_symbol(
                name, localvinfo.vtype, altname, None, None)
        else:
            varinfo = self.get_symbol(name, vtype, altname, None, None)
        return AST.ASTVariable(id, varinfo)

    def mk_register_variable(
            self,
            name: str,
            vtype: Optional["BCTyp"] = None,
            parameter: Optional[int] = None) -> AST.ASTVariable:
        id = self.new_id()
        altname = self.register_variable_name(name)
        if (
                altname
                and self.has_functiondef()
                and self.functiondef.has_localvar(altname)):
            localvinfo = self.functiondef.localvar(altname)
            varinfo = self.get_symbol(
                name, localvinfo.vtype, altname, parameter, None)
        else:
            varinfo = self.get_symbol(
                name, vtype, altname, parameter, None)
        return AST.ASTVariable(id, varinfo)

    def mk_stack_variable(
            self,
            offset: int,
            name: Optional[str] = None,
            vtype: Optional["BCTyp"] = None,
            parameter: Optional[int] = None) -> AST.ASTVariable:
        id = self.new_id()
        if name is None:
            if offset < 0:
                name = "localvar_" + str(-offset)
            elif offset == 0:
                name = "localvar_0"
            else:
                name = "argvar_" + str(offset)
        altname = self.stack_variable_name(offset)
        if (
                altname
                and self.has_functiondef()
                and self.functiondef.has_localvar(altname)):
            localvinfo = self.functiondef.localvar(altname)
            varinfo = self.get_symbol(
                name, localvinfo.vtype, altname, parameter, None)
        else:
            varinfo = self.get_symbol(
                name, vtype, altname, parameter, None)
        return AST.ASTVariable(id, varinfo)

    def is_variable_address(self, gaddr: int) -> Optional[str]:
        for ((name, _), vinfo) in self.symboltable.items():
            if vinfo.has_global_address():
                if vinfo.global_address == gaddr:
                    return name
        else:
            return None

    def mk_ignored_lval(self) -> AST.ASTLval:
        varinfo = ignoredvariable
        var = AST.ASTVariable(-1, varinfo)
        return AST.ASTLval(-1, var, AST.ASTNoOffset(-1))

    def mk_temp_lval(self) -> AST.ASTLval:
        tmpname = "temp" + str(self.new_tmp_id())
        varinfo = self.get_symbol(tmpname, None, None, None, None)
        id = self.new_id()
        var = AST.ASTVariable(id, varinfo)
        id = self.new_id()
        return AST.ASTLval(id, var, AST.ASTNoOffset(-1))

    def mk_lval(
            self,
            lhost: AST.ASTLHost,
            offset: AST.ASTOffset) -> AST.ASTLval:
        id = self.new_id()
        return AST.ASTLval(id, lhost, offset)

    def is_struct_field_address(self, gaddr: int) -> bool:
        for gvinfo in self.symboltable.values():
            if gvinfo.is_struct and gvinfo.is_global:
                compinfo = (cast("BCTypComp", gvinfo.vtype)).compinfo
                gvaddr = gvinfo.global_address
                gvextent = gvaddr + compinfo.byte_size()
                if gaddr >= gvaddr and gaddr < gvextent:
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False

    def get_struct_field_address(self, gaddr: int) -> AST.ASTExpr:
        gvname: Optional[str] = None
        gvinfo: Optional[AST.ASTVarInfo] = None

        for ((name, _), vinfo) in self.symboltable.items():
            if vinfo.is_struct and vinfo.is_global:
                compinfo = (cast("BCTypComp", vinfo.vtype)).compinfo
                gvaddr = vinfo.global_address
                gvextent = gvaddr + compinfo.byte_size()
                if gaddr >= gvaddr and gaddr < gvextent:
                    gvname = name
                    gvinfo = vinfo
                    break

        if gvname and gvinfo:
            compinfo = (cast("BCTypComp", gvinfo.vtype)).compinfo
            ioffset = gaddr - gvinfo.global_address
            fieldoffsets = compinfo.fieldoffsets()
            prevfinfo: Optional["BCFieldInfo"] = None
            prevoffset = -1
            if ioffset == 0:
                id = self.new_id()
                var = AST.ASTVariable(id, gvinfo)
                lval = self.mk_lval(var, AST.ASTNoOffset(-1))
                return self.mk_address_of(lval)

            for (foffset, finfo) in fieldoffsets:
                if ioffset == foffset:
                    id = self.new_id()
                    var = AST.ASTVariable(id, gvinfo)
                    offset = self.mk_field_offset(
                        finfo.fieldname, finfo.fieldtype, AST.ASTNoOffset(-1))
                    lval = self.mk_lval(var, offset)
                    if finfo.fieldtype.is_array:
                        return self.mk_lval_expr(lval)
                    else:
                        return self.mk_address_of(lval)

        raise Exception("Struct field not found for address " + hex(gaddr))

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

    def mk_variable_lval(self, name: str) -> AST.ASTLval:
        var = self.mk_variable(name)
        id = self.new_id()
        return AST.ASTLval(id, var, nooffset)

    def mk_register_variable_lval(
            self,
            name: str,
            vtype: Optional["BCTyp"] = None,
            parameter: Optional[int] = None) -> AST.ASTLval:
        id = self.new_id()
        var = self.mk_register_variable(name, vtype, parameter)
        return AST.ASTLval(id, var, nooffset)

    def mk_register_variable_expr(
            self, name: str,
            vtype: Optional["BCTyp"] = None,
            parameter: Optional[int] = None) -> AST.ASTExpr:
        id = self.new_id()
        lval = self.mk_register_variable_lval(name, vtype, parameter)
        return AST.ASTLvalExpr(id, lval)

    def mk_stack_variable_lval(
            self,
            offset: int,
            name: Optional[str] = None,
            vtype: Optional["BCTyp"] = None,
            parameter: Optional[int] = None) -> AST.ASTLval:
        id = self.new_id()
        var = self.mk_stack_variable(offset, name, vtype, parameter)
        return AST.ASTLval(id, var, nooffset)

    def mk_returnval_variable_lval(
            self,
            iaddr: str,
            vtype: Optional["BCTyp"]) -> AST.ASTLval:
        othername = self.other_variable_name("rtn_" + iaddr)
        if othername is not None and othername.startswith("ignore-"):
            return self.mk_ignored_lval()
        else:
            id = self.new_id()
            var = self.mk_returnval_variable(iaddr, vtype)
            return AST.ASTLval(id, var, nooffset)

    def mk_memref(self, memexp: AST.ASTExpr) -> AST.ASTMemRef:
        id = self.new_id()
        return AST.ASTMemRef(id, memexp)

    def mk_memref_lval(
            self,
            memexp: AST.ASTExpr,
            offset: AST.ASTOffset = AST.ASTNoOffset(-1)) -> AST.ASTLval:
        memref = self.mk_memref(memexp)
        id = self.new_id()
        return AST.ASTLval(id, memref, offset)

    def mk_memref_expr(
            self,
            memexp: AST.ASTExpr,
            offset: AST.ASTOffset = AST.ASTNoOffset(-1)) -> AST.ASTExpr:
        memreflval = self.mk_memref_lval(memexp, offset)
        id = self.new_id()
        return AST.ASTLvalExpr(id, memreflval)

    def mk_scalar_index_offset(
            self,
            index: int,
            offset: AST.ASTOffset = AST.ASTNoOffset(-1)) -> AST.ASTIndexOffset:
        indexexpr = self.mk_integer_constant(index)
        id = self.new_id()
        return AST.ASTIndexOffset(id, indexexpr, offset)

    def mk_expr_index_offset(
            self,
            indexexpr: AST.ASTExpr,
            offset: AST.ASTOffset = AST.ASTNoOffset(-1)) -> AST.ASTIndexOffset:
        id = self.new_id()
        return AST.ASTIndexOffset(id, indexexpr, offset)

    def mk_field_offset(
            self,
            fieldname: str,
            fieldtype: "BCTyp",
            offset: AST.ASTOffset = AST.ASTNoOffset(-1)) -> AST.ASTFieldOffset:
        id = self.new_id()
        return AST.ASTFieldOffset(id, fieldname, fieldtype, offset)

    def mk_lval_expr(self, lval: AST.ASTLval) -> AST.ASTExpr:
        id = self.new_id()
        return AST.ASTLvalExpr(id, lval)

    def mk_integer_constant(self, cvalue: int) -> AST.ASTIntegerConstant:
        gvinfo = AU.has_global_denotation(self.global_symbols(), hex(cvalue))
        id = self.new_id()
        return AST.ASTIntegerConstant(id, cvalue)

    def mk_string_constant(
            self, expr: AST.ASTExpr, cstr: str, saddr: str) -> AST.ASTStringConstant:
        id = self.new_id()
        return AST.ASTStringConstant(id, expr, cstr, saddr)

    def mk_assign(self, lval: AST.ASTLval, rhs: AST.ASTExpr) -> AST.ASTAssign:
        id = self.new_id()
        return AST.ASTAssign(id, lval, rhs)

    def mk_address_of(self, lval: AST.ASTLval) -> AST.ASTAddressOf:
        id = self.new_id()
        return AST.ASTAddressOf(id, lval)

    def mk_binary_op(
            self, op: str,
            exp1: AST.ASTExpr,
            exp2: AST.ASTExpr) -> AST.ASTExpr:
        if exp2.is_integer_constant and op == "lsl":
            expvalue = cast(AST.ASTIntegerConstant, exp2).cvalue
            if expvalue == 0:
                return exp1
        if exp1.is_integer_constant and exp2.is_integer_constant and op == "band":
            # 0 & x = x & 0 = 0
            exp1value = cast(AST.ASTIntegerConstant, exp1).cvalue
            exp2value = cast(AST.ASTIntegerConstant, exp2).cvalue
            if exp1value == 0:
                return exp1
            elif exp2value == 0:
                return exp2

        id = self.new_id()
        return AST.ASTBinaryOp(id, op, exp1, exp2)

    def mk_question(
            self,
            exp1: AST.ASTExpr,
            exp2: AST.ASTExpr,
            exp3: AST.ASTExpr) -> AST.ASTExpr:
        id = self.new_id()
        return AST.ASTQuestion(id, exp1, exp2, exp3)

    def mk_unary_op(self, op: str, exp: AST.ASTExpr) -> AST.ASTExpr:
        id = self.new_id()
        return AST.ASTUnaryOp(id, op, exp)

    def mk_cast_expr(self, tgttyp: str, exp: AST.ASTExpr) -> AST.ASTExpr:
        id = self.new_id()
        return AST.ASTCastE(id, tgttyp, exp)

    def mk_call(
            self,
            lval: Optional[AST.ASTLval],
            tgt: AST.ASTExpr,
            args: List[AST.ASTExpr]) -> AST.ASTCall:
        id = self.new_id()
        if not lval:
            lval = self.mk_ignored_lval()
        returntype = self.function_returntype(str(tgt))
        if returntype and returntype in ["void", "VOID"]:
            lval = self.mk_ignored_lval()
        return AST.ASTCall(id, lval, tgt, args)

    def rewrite(self, node: AST.ASTNode) -> AST.ASTNode:
        if node.is_ast_stmt:
            return self.rewrite_stmt(cast(AST.ASTStmt, node))

        return node

    def rewrite_stmt(self, stmt: AST.ASTStmt) -> AST.ASTStmt:
        if stmt.is_ast_return:
            return self.rewrite_return(cast(AST.ASTReturn, stmt))
        if stmt.is_ast_block:
            return self.rewrite_block(cast(AST.ASTBlock, stmt))
        if stmt.is_ast_branch:
            return self.rewrite_branch(cast(AST.ASTBranch, stmt))
        if stmt.is_ast_instruction_sequence:
            return self.rewrite_instruction_sequence(
                cast(AST.ASTInstrSequence, stmt))

        return stmt

    def rewrite_return(self, retstmt: AST.ASTReturn) -> AST.ASTStmt:
        return retstmt

    def rewrite_block(self, block: AST.ASTBlock) -> AST.ASTStmt:
        return AST.ASTBlock(block.id, [self.rewrite_stmt(s) for s in block.stmts])

    def rewrite_branch(self, branch: AST.ASTBranch) -> AST.ASTStmt:
        return AST.ASTBranch(
            branch.id,
            self.rewrite_expr(branch.condition),
            self.rewrite_stmt(branch.ifstmt),
            self.rewrite_stmt(branch.elsestmt),
            branch.relative_offset)

    def rewrite_instruction_sequence(
            self, instrseq: AST.ASTInstrSequence) -> AST.ASTStmt:
        return AST.ASTInstrSequence(
            instrseq.id,
            [self.rewrite_instruction(i) for i in instrseq.instructions])

    def rewrite_instruction(self, instr: AST.ASTInstruction) -> AST.ASTInstruction:
        if instr.is_ast_assign:
            return self.rewrite_assign(cast(AST.ASTAssign, instr))
        if instr.is_ast_call:
            return self.rewrite_call(cast(AST.ASTCall, instr))

        return instr

    def rewrite_assign(self, assign: AST.ASTAssign) -> AST.ASTInstruction:
        return AST.ASTAssign(
            assign.id,
            self.rewrite_lval(assign.lhs),
            self.rewrite_expr(assign.rhs))

    def rewrite_call(self, call: AST.ASTCall) -> AST.ASTInstruction:
        return call

    def rewrite_lval_to_indexed_array_lval(
            self,
            lvalid: int,
            memexp: AST.ASTBinaryOp,
            default: Callable[[], AST.ASTLval]) -> AST.ASTLval:
        base = cast(AST.ASTIntegerConstant, memexp.exp1)
        if base.macroname and (base.macroname, "__none__") in self.symboltable:
            basevar = self.symboltable[(base.macroname, "__none__")]
            basetype = basevar.vtype
            if basetype and basetype.is_array:
                basetype = cast("BCTypArray", basetype)
                elsize = basetype.tgttyp.byte_size()
                if memexp.exp2.is_ast_binary_op:
                    indexexp = cast(AST.ASTBinaryOp, memexp.exp2)
                    if indexexp.op in ["lsl", "shiftlt"]:
                        if indexexp.exp2.is_integer_constant:
                            shiftamount = cast(
                                AST.ASTIntegerConstant, indexexp.exp2)
                            if elsize == 4 and shiftamount.cvalue == 2:
                                newindexexp = self.mk_expr_index_offset(
                                    indexexp.exp1)
                                bvar = self.mk_variable(base.macroname)
                                lvalnewid = self.new_id()
                                return AST.ASTLval(lvalnewid, bvar, newindexexp)
                            else:
                                print("rewrite-to-array: 1")
                                return default()
                        else:
                            print("rewrite-to-array: 2")
                            return default()
                    else:
                        print("rewrite-to-array: 3")
                        return default()
                else:
                    print("rewrite-to-array: 4")
                    return default()
            else:
                print("rewrite-to-array: 5")
                return default()
        else:
            print("rewrite-to_array: 6")
            return default()


    def rewrite_lval_to_fieldoffset_lval(
            self,
            lvalid: int,
            memexp: AST.ASTBinaryOp,
            default: Callable[[], AST.ASTLval]) -> AST.ASTLval:
        intoffset = cast(AST.ASTIntegerConstant, memexp.exp2)
        base = cast(AST.ASTLvalExpr, memexp.exp1)
        if base.is_ast_substituted_expr:
            base = cast(AST.ASTSubstitutedExpr, base)
            basexpr = base.substituted_expr
            if basexpr.is_ast_lval_expr:
                base = cast(AST.ASTLvalExpr, basexpr)
        if base.lval.offset.is_index_offset:
            if base.lval.lhost.ctype and base.lval.lhost.ctype.is_array:
                basetype = cast("BCTypArray", base.lval.lhost.ctype)
                if basetype.tgttyp.is_pointer:
                    basetgttype = cast("BCTypPtr", basetype.tgttyp)
                    if basetgttype.tgttyp.is_struct:
                        structtyp = cast("BCTypComp", basetgttype.tgttyp)
                        compinfo = structtyp.compinfo
                        finfo = compinfo.field_at_offset(intoffset.cvalue)[0]
                        fieldoffset = self.mk_field_offset(
                            finfo.fieldname, finfo.fieldtype, AST.ASTNoOffset(-1))
                        newhostid = self.new_id()
                        newmemref = AST.ASTMemRef(newhostid, memexp.exp1)
                        newlvalid = self.new_id()
                        newlval = AST.ASTLval(
                            newlvalid, newmemref, fieldoffset)
                        return newlval
                    else:
                        return default()
                else:
                    return default()
            else:
                return default()
        else:
            return default()

    def rewrite_lval(self, lval: AST.ASTLval) -> AST.ASTLval:

        def default() -> AST.ASTLval:
            return AST.ASTLval(
                lval.id,
                self.rewrite_lhost(lval.lhost),
                self.rewrite_offset(lval.offset))

        lhost = self.rewrite_lhost(lval.lhost)
        offset = self.rewrite_offset(lval.offset)
        if lhost.is_memref and offset.is_no_offset:
            lhost = cast(AST.ASTMemRef, lhost)
            if lhost.memexp.is_ast_binary_op:
                memexp = cast(AST.ASTBinaryOp, lhost.memexp)
                if memexp.op == "plus" and memexp.exp1.is_integer_constant:
                    return self.rewrite_lval_to_indexed_array_lval(lval.id, memexp, default)

                elif (
                        memexp.op == "plus"
                        and memexp.exp1.is_ast_lval_expr
                        and memexp.exp2.is_integer_constant):
                    return self.rewrite_lval_to_fieldoffset_lval(lval.id, memexp, default)

                else:
                    return default()
            else:
                return default()

        return AST.ASTLval(
            lval.id,
            self.rewrite_lhost(lval.lhost),
            self.rewrite_offset(lval.offset))

    def rewrite_lhost(self, lhost: AST.ASTLHost) -> AST.ASTLHost:
        if lhost.is_variable:
            return lhost
        if lhost.is_memref:
            return self.rewrite_memref(cast(AST.ASTMemRef, lhost))

        return lhost

    def rewrite_memref(self, memref: AST.ASTMemRef) -> AST.ASTLHost:
        return AST.ASTMemRef(memref.id, self.rewrite_expr(memref.memexp))

    def rewrite_offset(self, offset: AST.ASTOffset) -> AST.ASTOffset:
        if offset.is_no_offset:
            return offset
        if offset.is_field_offset:
            return offset
        if offset.is_index_offset:
            return offset

        return offset

    def rewrite_expr(self, expr: AST.ASTExpr) -> AST.ASTExpr:
        if expr.is_ast_constant:
            return self.rewrite_constant(cast(AST.ASTConstant, expr))
        if expr.is_ast_substituted_expr:
            return self.rewrite_substituted_expr(cast(AST.ASTSubstitutedExpr, expr))
        if expr.is_ast_lval_expr:
            return self.rewrite_lval_expr(cast(AST.ASTLvalExpr, expr))
        if expr.is_ast_cast_expr:
            return self.rewrite_cast_expr(cast(AST.ASTCastE, expr))
        if expr.is_ast_unary_op:
            return self.rewrite_unary_op(cast(AST.ASTUnaryOp, expr))
        if expr.is_ast_binary_op:
            return self.rewrite_binary_op(cast(AST.ASTBinaryOp, expr))
        if expr.is_ast_question:
            return self.rewrite_question(cast(AST.ASTQuestion, expr))

        return expr

    def rewrite_constant(self, expr: AST.ASTConstant) -> AST.ASTExpr:
        return expr

    def rewrite_substituted_expr(self, expr: AST.ASTSubstitutedExpr) -> AST.ASTExpr:
        return AST.ASTSubstitutedExpr(
            expr.id,
            self.rewrite_lval(expr.lval),
            expr.assign_id,
            self.rewrite_expr(expr.substituted_expr))

    def rewrite_lval_expr(self, expr: AST.ASTLvalExpr) -> AST.ASTExpr:
        return AST.ASTLvalExpr(expr.id, self.rewrite_lval(expr.lval))

    def rewrite_cast_expr(self, expr: AST.ASTCastE) -> AST.ASTExpr:
        return expr

    def rewrite_unary_op(self, expr: AST.ASTUnaryOp) -> AST.ASTExpr:
        return AST.ASTUnaryOp(expr.id, expr.op, self.rewrite_expr(expr.exp))

    def rewrite_binary_op(self, expr: AST.ASTBinaryOp) -> AST.ASTExpr:
        return AST.ASTBinaryOp(
            expr.id,
            expr.op,
            self.rewrite_expr(expr.exp1),
            self.rewrite_expr(expr.exp2))

    def rewrite_question(self, expr: AST.ASTQuestion) -> AST.ASTExpr:
        return expr

    def __str__(self) -> str:
        lines: List[str] = []
        for r in self._spans:
            lines.append(str(r))
        return "\n".join(lines)
