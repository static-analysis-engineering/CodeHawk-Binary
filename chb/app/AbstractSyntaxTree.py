# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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
    Any, cast, Dict, List, Mapping, NewType, Optional, Sequence, Tuple, Union)

import chb.app.ASTNode as AST


ASTSpanRecord = NewType(
    "ASTSpanRecord", Dict[str, Union[int, List[Dict[str, Union[str, int]]]]])

VariableNamesRec = NewType(
    "VariableNamesRec", Dict[str, List[Dict[str, Union[Tuple[str, str], str]]]])


unknowntype = AST.ASTTNamed(-1, "unknown")
ignoredvariable = AST.ASTVarInfo(-1, "ignored")


class VariableNames:

    def __init__(self, namerecords: VariableNamesRec) -> None:
        self._namerecords = namerecords

    @property
    def namerecords(self) -> VariableNamesRec:
        return self._namerecords

    def has_variable(self, v: str) -> bool:
        return v in self.namerecords

    def name_at_addr(self, v: str, addr: str) -> Optional[str]:
        if self.has_variable(v):
            vinfo = self.namerecords[v]
            addri = int(addr, 16)
            for s in vinfo:
                vlow = int(s["span"][0], 16)
                vhigh = int(s["span"][1], 16)
                if vlow <= addri and addri <= vhigh:
                    return cast(str, s["altname"])
            else:
                return None
        else:
            return None

        
class AbstractSyntaxTree:

    def __init__(
            self,
            faddr: str,
            variablenames: VariableNamesRec = cast(VariableNamesRec, {}),
            functionsummaries: Dict[str, Any] = {})-> None:
        self._faddr = faddr
        self._counter = 0
        self._spans: List[ASTSpanRecord] = []
        self._variablenames = VariableNames(variablenames)
        self._functionsummaries = functionsummaries
        self._currentaddr: Optional[str] = None
        self._symboltable: Dict[Tuple[str, str], AST.ASTVarInfo] = {}
        self._symboltable[("ignored", "__none__")] = ignoredvariable
        self._vardecls: Dict[str, AST.ASTVarDeclaration] = {}

    @property
    def spans(self) -> List[ASTSpanRecord]:
        return self._spans

    @property
    def symboltable(self) -> Dict[Tuple[str, str], AST.ASTVarInfo]:
        return self._symboltable

    @property
    def vardecls(self) -> Dict[str, AST.ASTVarDeclaration]:
        return self._vardecls

    def has_symbol(self, name: str, altname: Optional[str] = None) -> bool:
        index = (name, altname) if altname else (name, "__none__")
        return index in self.symboltable

    def _symbol(self, name: str, altname: Optional[str] = None) -> AST.ASTVarInfo:
        index = (name, altname) if altname else (name, "__none__")
        if self.has_symbol(name, altname = altname):
            return self.symboltable[index]
        else:
            print("Internal error: symbol not found: " + str(index))
            exit(1)

    def add_symbol(
            self,
            vname: str,
            vtype: AST.ASTVType = unknowntype,
            altname: Optional[str] = None) -> None:
        id = self.new_id()
        varinfo = AST.ASTVarInfo(id, vname, vtype = vtype, altname = altname)
        index = (vname, altname) if altname else (vname, "__none__")
        self._symboltable[index] = varinfo

    def get_symbol(
            self,
            name: str,
            altname: Optional[str] = None,
            vtype: AST.ASTVType = unknowntype) -> AST.ASTVarInfo:
        if not self.has_symbol(name, altname):
            self.add_symbol(name, vtype = vtype, altname = altname)
        return self._symbol(name, altname = altname)

    def replace_symbol(
            self,
            name: str,
            vtype: AST.ASTVType) -> AST.ASTVarInfo:
        if not self.has_symbol(name):
            self.add_symbol(name, vtype = vtype)
        else:
            vinfo = self.get_symbol(name)
            replacement = AST.ASTVarInfo(vinfo.id, name, vtype)
            self._symboltable[(name, "__none__")] = replacement
        return self._symbol(name)

    def new_id(self) -> int:
        id = self._counter
        self._counter += 1
        return id

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

    def set_current_addr(self, addr: str) -> None:
        """Set address of current instruction.

        Only used if incorporating user-provided alternate variable names,
        otherwise unused.
        """
        self._currentaddr = addr

    def name_at_addr(self, v: str) -> Optional[str]:
        """Retrieve the alternate name of a variable at a given address.

        Only used if incorporating user-provided alternate variable names,
        otherwise not relevant.
        """
        if self._currentaddr:
            return self._variablenames.name_at_addr(v, self._currentaddr)
        else:
            return None

    def function_summary(self, name: str) -> Dict[str, Any]:
        if name in self._functionsummaries:
            return self._functionsummaries[name]
        else:
            return {}

    def function_returntype(self, name: str) -> Optional[str]:
        if self.function_summary(name):
            fs = self.function_summary(name)
            if "returntype" in fs and isinstance(fs["returntype"], str):
                return fs["returntype"]
            else:
                return None
        else:
            return None

    def mk_block(self, stmts: List[AST.ASTStmt]) -> AST.ASTBlock:
        id = self.new_id()
        return AST.ASTBlock(id, stmts)

    def mk_branch(
            self,
            condition: AST.ASTExpr,
            ifbranch: AST.ASTStmt,
            elsebranch: AST.ASTStmt) -> AST.ASTStmt:
        id = self.new_id()
        return AST.ASTBranch(id, condition, ifbranch, elsebranch)

    def mk_instr_sequence(self, instrs: List[AST.ASTInstruction]) -> AST.ASTInstrSequence:
        id = self.new_id()
        return AST.ASTInstrSequence(id, instrs)

    def mk_void_type(self) -> AST.ASTTVoid:
        id = self.new_id()
        return AST.ASTTVoid(id)

    def mk_integer_type(self, ikind: str) -> AST.ASTTInt:
        id = self.new_id()
        return AST.ASTTInt(id, ikind)

    def mk_pointer_type(self, tgttype: AST.ASTVType) -> AST.ASTTPtr:
        id = self.new_id()
        return AST.ASTTPtr(id, tgttype)

    def mk_function_signature_type(
            self,
            returntype: AST.ASTVType,
            argtypes: List[Tuple[str, AST.ASTVType]]) -> AST.ASTTFun:
        id = self.new_id()
        return AST.ASTTFun(id, returntype, argtypes)

    def mk_scalar_type(self, tname: str) -> AST.ASTVType:
        if tname == "void":
            return self.mk_void_type()
        else:
            return self.mk_integer_type(tname)

    def mk_complex_type(self, t: Dict[str, Any]) -> AST.ASTVType:
        if "key" in t:
            if t["key"] == "ptr":
                if "tgt" in t:
                    if isinstance(t["tgt"], str):
                        tgttype = self.mk_scalar_type(t["tgt"])
                        return self.mk_pointer_type(tgttype)
                    else:
                        return unknowntype
                else:
                    return unknowntype
            else:
                return unknowntype
        else:
            return unknowntype

    def add_function_declaration(self, name: str) -> None:
        fs = self.function_summary(name)
        if fs:
            if "returntype" in fs:
                if isinstance(fs["returntype"], str):
                    returntype = self.mk_scalar_type(fs["returntype"])
                else:
                    returntype = self.mk_complex_type(fs["returntype"])
            else:
                returntype = self.mk_void_type()
            argtypes: List[Tuple[str, AST.ASTVType]] = []
            if "args" in fs:
                for arg in fs["args"]:
                    if "name" in arg:
                        argname = arg["name"]
                    else:
                        argname = "_"
                    if "type" in arg:
                        if isinstance(arg["type"], str):
                            argtype = self.mk_scalar_type(arg["type"])
                        else:
                            argtype = self.mk_complex_type(arg["type"])
                    else:
                        argtype = unknowntype
                    argtypes.append((argname, argtype))
            else:
                pass
            ftype = self.mk_function_signature_type(returntype, argtypes)
            fvar = self.replace_symbol(name, vtype = ftype)
            id = self.new_id()
            vardecl = AST.ASTVarDeclaration(id, fvar)
            self._vardecls[name] = vardecl
        else:
            print("no summary found for " + name)

    def mk_variable(self, name: str) -> AST.ASTVariable:
        id = self.new_id()
        altname = self.name_at_addr(name)
        varinfo = self.get_symbol(name, altname = altname)
        return AST.ASTVariable(id, varinfo)

    def mk_ignored_lval(self) -> AST.ASTLval:
        varinfo = ignoredvariable
        var = AST.ASTVariable(-1, varinfo)
        return AST.ASTLval(-1, var, AST.ASTNoOffset(-1))

    def mk_lval(
            self,
            lhost: Union[AST.ASTVariable, AST.ASTMemRef],
            offset: AST.ASTOffset) -> AST.ASTLval:
        id = self.new_id()
        return AST.ASTLval(id, lhost, offset)

    def mk_variable_lval(
            self,
            name: str,
            offset: AST.ASTOffset = AST.ASTNoOffset(-1)) -> AST.ASTLval:
        var = self.mk_variable(name)
        id = self.new_id()
        return AST.ASTLval(id, var, offset)

    def mk_variable_expr(
            self,
            name: str,
            offset: AST.ASTOffset = AST.ASTNoOffset(-1)) -> AST.ASTExpr:
        varlval = self.mk_variable_lval(name, offset)
        id = self.new_id()
        return AST.ASTLvalExpr(id, varlval)

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

    def mk_lval_expr(self, lval: AST.ASTLval) -> AST.ASTExpr:
        id = self.new_id()
        return AST.ASTLvalExpr(id, lval)

    def mk_integer_constant(self, cvalue: int) -> AST.ASTIntegerConstant:
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
