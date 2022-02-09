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
    from chb.bctypes.BCTyp import BCTyp, BCTypFun, BCTypComp, BCTypArray
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
            ignore_return_value: List[str] = []) -> None:
        self._faddr = faddr
        self._fname = fname  # same as faddr if no name provided
        self._counter = 0
        self._vcounter = 0
        self._tmpcounter = 0
        self._spans: List[ASTSpanRecord] = []
        self._variablenames = VariableNames(variablenames)
        self._ignore_return_value = ignore_return_value
        self._symbolicaddrs = symbolicaddrs
        self._currentaddr: Optional[str] = None
        self._symboltable: Dict[Tuple[str, str], AST.ASTVarInfo] = {}
        self._symboltable[("ignored", "__none__")] = ignoredvariable
        self._unsupported: Dict[str, List[str]] = {}
        self._fprototype: Optional["BCVarInfo"] = None
        self._functiondef: Optional["BCFunctionDefinition"] = None

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

    def function_argument(self, index: int) -> Optional["BCFunArg"]:
        """Return the argument with the given index (zero-based)."""

        if self.has_function_prototype():
            ftype = cast("BCTypFun", self.function_prototype().vtype)
            if ftype.argtypes:
                if len(ftype.argtypes.funargs) > index:
                    return ftype.argtypes.funargs[index]
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
            globaladdress: Optional[int]) -> None:
        id = self.new_id()
        varinfo = AST.ASTVarInfo(
            id, vname, vtype, altname, parameter, globaladdress)
        index = (vname, altname) if altname else (vname, "__none__")
        self._symboltable[index] = varinfo

    def get_symbol(
            self,
            name: str,
            vtype: Optional["BCTyp"],
            altname: Optional[str],
            parameter: Optional[int],
            globaladdress: Optional[int]) -> AST.ASTVarInfo:
        if not self.has_symbol(name, altname):
            self.add_symbol(name, vtype, altname, parameter, globaladdress)
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

    def mk_stack_variable(self, offset: int) -> AST.ASTVariable:
        id = self.new_id()
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
                name, localvinfo.vtype, altname, None, None)
        else:
            varinfo = self.get_symbol(
                name, None, altname, None, None)
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

    def mk_stack_variable_lval(self, offset: int) -> AST.ASTLval:
        id = self.new_id()
        var = self.mk_stack_variable(offset)
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

    def mk_binary_op(self, op: str, exp1: AST.ASTExpr, exp2: AST.ASTExpr) -> AST.ASTExpr:
        id = self.new_id()
        return AST.ASTBinaryOp(id, op, exp1, exp2)

    def mk_question(
            self, exp1: AST.ASTExpr, exp2: AST.ASTExpr, exp3: AST.ASTExpr) -> AST.ASTExpr:
        id = self.new_id()
        return AST.ASTQuestion(id, exp1, exp2, exp3)

    def mk_unary_op(self, op: str, exp: AST.ASTExpr) -> AST.ASTExpr:
        id = self.new_id()
        return AST.ASTUnaryOp(id, op, exp)

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

    def __str__(self) -> str:
        lines: List[str] = []
        for r in self._spans:
            lines.append(str(r))
        return "\n".join(lines)
