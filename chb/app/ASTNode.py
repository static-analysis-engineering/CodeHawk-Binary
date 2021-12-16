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
"""Node in abstract syntax tree.

Grammar (based on CIL (ref https://people.eecs.berkeley.edu/~necula/cil/))

file: global list

global: GVarDecl varinfo
      | GVar varinfo
      | GFun fundec

fundec: varinfo (varinfo list) (varinfo list) block

block: stmt list

stmt: Instr instr list
    | Return expr 
    | If exp block block 
    | Block block

instr: Set lval exp
     | Call lval expr exp list

lval: lhost offset

lhost: Var varinfo
     | Mem exp

offset: NoOffset
      | Field <fieldinfo> offset
      | Index exp offset

exp: IntConstant <int>
    | StringConstant <int>
    | Lval lval
    | UnOp unop exp
    | BinOp binop exp exp
    | AddOf lval

unop: Neg | BNot | LNot

binop: Plus | Minus

typ: TVoid
   | TInt <ikind>
   | TPtr typ
   | TArray typ exp option
   | TFun typ (string * typ) list
   | TNamed string

varinfo: string typ storage

storage: NoStorage
       | Static
       | Register
       | Extern

"""
import copy

from abc import ABC, abstractmethod
from typing import (
    Any, cast, Dict, List, Mapping, NewType, Optional, Sequence, Set, Tuple, Union)

import chb.app.ASTUtil as UA


ASTNodeRecord = NewType(
    "ASTNodeRecord", Dict[str, Union[List[str], List[int], int, str]])


c_indent = 3


operators = {
    "eq": " == ",
    "gt": " > ",    
    "minus": " - ",
    "ne": " != ",
    "plus": " + "    
    }


class ASTNode:

    def __init__(self, id: int, tag: str) -> None:
        self._id = id
        self._tag = tag

    @property
    def id(self) -> int:
        return self._id

    @property
    def tag(self) -> str:
        return self._tag

    def transform_instr_subx(
            self, usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> "ASTNode":
        return self

    def reduce(
            self,
            mapping: Dict[int, int], live_x: Mapping[int, Set[str]] = {}) -> "ASTNode":
        return self

    def variables_used(self) -> Set[str]:
        return set([])

    def callees(self) -> Set[str]:
        return set([])

    def noderecord(self) -> ASTNodeRecord:
        result: Dict[str, Any] = {}
        result["id"] = self.id
        result["tag"] = str(self.tag)
        return cast(ASTNodeRecord, result)

    def serialize(self) -> List[ASTNodeRecord]:
        return []

    def to_c_like(self, sp: int = 0) -> str:
        return (" " * sp) + str(self.id) + ":" + self.tag

    def to_string(self, sp: int = 0) -> str:
        return (" " * sp) + str(self.id) + ":" + self.tag

    def __str__(self) -> str:
        return str(self.id) + ":" + self.tag


class ASTVType(ASTNode):

    def __init__(self, id: int, tag: str) -> None:
        ASTNode.__init__(self, id, tag)

    @property
    def is_function_type(self) -> bool:
        return False


class ASTTNamed(ASTVType):

    def __init__(self, id: int, name: str) -> None:
        ASTVType.__init__(self, id, "tnamed")
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def to_c_like(self, sp: int = 0) -> str:
        return self.name


class ASTTVoid(ASTVType):

    def __init__(self, id: int) -> None:
        ASTVType.__init__(self, id, "tvoid")

    def to_c_like(self, sp: int = 0) -> str:
        return "void"


class ASTTInt(ASTVType):

    def __init__(self, id: int, ikind: str) -> None:
        ASTVType.__init__(self, id, "tint")
        self._ikind = ikind

    @property
    def ikind(self) -> str:
        return self._ikind

    def to_c_like(self, sp: int = 0) -> str:
        return self.ikind


class ASTTPtr(ASTVType):

    def __init__(self, id: int, tgttype: "ASTVType") -> None:
        ASTVType.__init__(self, id, "tptr")
        self._tgttype = tgttype

    @property
    def tgttype(self) -> "ASTVType":
        return self._tgttype

    def to_c_like(self, sp: int = 0) -> str:
        return self.tgttype.to_c_like(sp) + " *"


class ASTTFun(ASTVType):

    def __init__(
            self,
            id: int,
            returntype: "ASTVType",
            argtypes: List[Tuple[str, "ASTVType"]]) -> None:
        ASTVType.__init__(self, id, "tfun")
        self._returntype = returntype
        self._argtypes = argtypes

    @property
    def returntype(self) -> "ASTVType":
        return self._returntype

    @property
    def argtypes(self) -> List[Tuple[str, "ASTVType"]]:
        return self._argtypes

    @property
    def is_function_type(self) -> bool:
        return True

    def to_c_like(self, sp: int = 0) -> str:
        return (
            "tfun: "
            + "("
            + ", ".join(t.to_c_like(sp) + " " + n for (n, t) in self.argtypes)
            + ") -> "
            + self.returntype.to_c_like(sp))

    
class ASTFile(ASTNode):

    def __init__(
            self,
            id: int,
            globals: List["ASTGlobal"],
            filename: str = "") -> None:
        ASTNode.__init__(self, id, "file")
        self._globals = globals
        self._filename = filename

    @property
    def globals(self) -> List["ASTGlobal"]:
        return self._globals

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def var_declarations(self) -> List["ASTVarDeclaration"]:
        result: List["ASTVarDeclaration"] = []
        for g in self.globals:
            if g.is_var_declaration:
                result.append(cast("ASTVarDeclaration", g))
        return result

    @property
    def var_definitions(self) -> List["ASTVarDefinition"]:
        result: List["ASTVarDefinition"] = []
        for g in self.globals:
            if g.is_var_definition:
                result.append(cast("ASTVarDefinition", g))
        return result

    @property
    def fun_definitions(self) -> List["ASTFunDefinition"]:
        result: List["ASTFunDefinition"] = []
        for g in self.globals:
            if g.is_fun_definition:
                result.append(cast("ASTFunDefinition", g))
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        g: "ASTGlobal"
        for g in self.var_declarations:
            result.extend(g.serialize())
        for g in self.var_definitions:
            result.extend(g.serialize())
        for g in self.fun_definitions:
            result.extend(g.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        lines: List[str] = []
        if self.filename:
            lines.append("/* " + self.filename + "*/")
        for vdecl in self.var_declarations:
            lines.append(vdecl.to_c_like(sp))
        for vdef in self.var_definitions:
            lines.append(vdef.to_c_like(sp))
        for fdef in self.fun_definitions:
            lines.append(fdef.to_c_like(sp))
        return "\n".join(lines)
                         

class ASTGlobal(ASTNode):

    def __init__(self, id: int, tag: str) -> None:
        ASTNode.__init__(self, id, tag)

    @property
    def is_var_declaration(self) -> bool:
        return False

    @property
    def is_var_definition(self) -> bool:
        return False

    @property
    def is_fun_definition(self) -> bool:
        return False


class ASTVarDeclaration(ASTGlobal):

    def __init__(self, id: int, varinfo: "ASTVarInfo") -> None:
        ASTGlobal.__init__(self, id, "var-decl")
        self._varinfo = varinfo

    @property
    def varinfo(self) -> "ASTVarInfo":
        return self._varinfo

    @property
    def is_var_declaration(self) -> bool:
        return True

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [self.varinfo.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.varinfo.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        return self.varinfo.to_c_like(sp) + ";"


class ASTVarDefinition(ASTGlobal):

    def __init__(self, id: int, varinfo: "ASTVarInfo") -> None:
        ASTGlobal.__init__(self, id, "var-def")
        self._varinfo = varinfo

    @property
    def varinfo(self) -> "ASTVarInfo":
        return self._varinfo

    @property
    def is_var_definition(self) -> bool:
        return True

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = self.varinfo.id
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.varinfo.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        vtype = self.varinfo.vtype.to_c_like(sp)
        return vtype + " " + self.varinfo.displayname + ";"
       

class ASTFunDefinition(ASTGlobal):

    def __init__(
            self,
            id: int,
            svar: "ASTVarInfo",
            sformals: List["ASTVarInfo"],
            slocals: List["ASTVarInfo"],
            sbody: "ASTBlock") -> None:
        ASTGlobal.__init__(self, id, "fun-def")
        self._svar = svar
        self._sformals = sformals
        self._slocals = slocals
        self._sbody = sbody

    @property
    def svar(self) -> "ASTVarInfo":
        return self._svar

    @property
    def sformals(self) -> List["ASTVarInfo"]:
        return self._sformals

    @property
    def slocals(self) -> List["ASTVarInfo"]:
        return self._slocals

    @property
    def sbody(self) -> "ASTBlock":
        return self._sbody

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [self.svar.id, self.sbody.id]
        result["formals"] = [f.id for f in self.sformals]
        result["locals"] = [l.id for l in self.slocals]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        for f in self.sformals:
            result.extend(f.serialize())
        for l in self.slocals:
            result.extend(l.serialize())
        result.extend(self.sbody.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(self.svar.to_c_like(sp) + " {")
        for l in self.slocals:
            lines.append(l.to_c_like(sp + c_indent))
        lines.append("")
        lines.append(self.sbody.to_c_like(sp + 2))
        lines.append("}")
        return "\n".join(lines)

    def __str__(self) -> str:
        return str(self.svar)
            
                 

class ASTStmt(ASTNode):

    def __init__(self, id: int, tag: str) -> None:
        ASTNode.__init__(self, id, tag)

    def is_empty(self) -> bool:
        return False

    def address_taken(self) -> Set[str]:
        return set([])

    @abstractmethod
    def live_e(self, live_x: Set[str], node_live_x: Dict[int, Set[str]]) -> Set[str]:
        """Return the live variables at node entry given live variables at node exit.

        live_x: the set of live variables at node exit
        node_live_x: mapping from instruction nodes to live exit variables
        """
        ...

    @abstractmethod
    def usedefs_x(
            self,
            usedefs_e: Dict[str, List[Tuple[int, "ASTExpr"]]],
            addresstaken: Set[str],
            node_usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> Dict[
                str, List[Tuple[int, "ASTExpr"]]]:
        """Return the reaching definitions of variables that may be substituted.
        
        usedefs_e: the reaching definitions at node entry
                   Var -> [Label * expr]
        addresstaken: set of variables whose address is taken
        node_usedefs_e: mapping from instruction nodes to reaching definitions
                        Label -> Var -> [Label * expr]
        """
        ...
            
    def transform_instr_subx(
            self,
            usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> "ASTStmt":
        return self

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTStmt":
        return self

    def variables_used(self) -> Set[str]:
        return set([])

    def callees(self) -> Set[str]:
        return set([])


class ASTBlock(ASTStmt):

    def __init__(self, id: int, stmts: List["ASTStmt"]) -> None:
        ASTStmt.__init__(self, id, "block")
        self._stmts = stmts

    @property
    def stmts(self) -> Sequence["ASTStmt"]:
        return self._stmts

    def is_empty(self) -> bool:
        return all(s.is_empty() for s in self.stmts)

    def address_taken(self) -> Set[str]:
        if self.is_empty():
            return set([])
        else:
            return self.stmts[0].address_taken().union(
                *(s.address_taken() for s in self.stmts[1:]))

    def variables_used(self) -> Set[str]:
        if self.is_empty():
            return set([])
        else:
            return self.stmts[0].variables_used().union(
                *(s.variables_used() for s in self.stmts[1:]))

    def callees(self) -> Set[str]:
        if self.is_empty():
            return set([])
        else:
            return self.stmts[0].callees().union(
                *(s.callees() for s in self.stmts[1:]))

    def live_e(self, live_x: Set[str], result: Dict[int, Set[str]]) -> Set[str]:
        sxit = live_x.copy()
        for s in reversed(self.stmts):
            sxit = s.live_e(sxit, result)
        return sxit

    def usedefs_x(
            self,
            usedefs_e: Dict[str, List[Tuple[int, "ASTExpr"]]],
            addresstaken: Set[str],
            node_usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> Dict[
                str, List[Tuple[int, "ASTExpr"]]]:
        usedefs: Dict[str, List[Tuple[int, "ASTExpr"]]] = copy.deepcopy(usedefs_e)
        for s in self.stmts:
            usedefs = s.usedefs_x(usedefs, addresstaken, node_usedefs_e)
        return usedefs

    def transform_instr_subx(
            self,
            usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> "ASTBlock":
        return ASTBlock(self.id, [s.transform_instr_subx(usedefs_e) for s in self.stmts])

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTBlock":
        return ASTBlock(self.id, [s.reduce(mapping, live_x) for s in self.stmts])

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [s.id for s in self.stmts]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        for s in self.stmts:
            result.extend(s.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        lines: List[str] = []
        for s in self.stmts:
            lines.append(s.to_c_like(sp))
        return "\n".join(lines)

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        lines.append("\n".join(s.to_string(sp + 2) for s in self.stmts))
        return "\n".join(lines)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append(ASTNode.__str__(self))
        lines.append("\n".join(str(s) for s in self.stmts))
        return "\n".join(lines)


class ASTInstrSequence(ASTStmt):

    def __init__(self, id: int, instrs: List["ASTInstruction"]) -> None:
        ASTStmt.__init__(self, id, "instrs")
        self._instrs: List["ASTInstruction"] = instrs
        self._aexp: Dict[int, List["ASTExpr"]] = {}

    @property
    def instructions(self) -> Sequence["ASTInstruction"]:
        return self._instrs

    def is_empty(self) -> bool:
        return len(self.instructions) == 0

    def address_taken(self) -> Set[str]:
        if self.is_empty():
            return set([])
        else:
            return self.instructions[0].address_taken().union(
                *(i.address_taken() for i in self.instructions))

    def variables_used(self) -> Set[str]:
        if self.is_empty():
            return set([])
        else:
            return self.instructions[0].variables_used().union(
                *(i.variables_used() for i in self.instructions))

    def callees(self) -> Set[str]:
        if self.is_empty():
            return set([])
        else:
            return self.instructions[0].callees().union(
                *(i.callees() for i in self.instructions))

    def live_e(self, live_x: Set[str], result: Dict[int, Set[str]]) -> Set[str]:
        ixtlive = live_x.copy()
        for i in reversed(self.instructions):
            ixtlive = i.live_e(ixtlive, result)
        return ixtlive

    def usedefs_x(
            self,
            usedefs_e: Dict[str, List[Tuple[int, "ASTExpr"]]],
            addresstaken: Set[str],
            node_usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> Dict[
                str, List[Tuple[int, "ASTExpr"]]]:
        usedefs: Dict[str, List[Tuple[int, "ASTExpr"]]] = copy.deepcopy(usedefs_e)
        for i in self.instructions:
            usedefs = i.usedefs_x(usedefs, addresstaken, node_usedefs_e)
        return usedefs

    def transform_instr_subx(
            self,
            usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> "ASTInstrSequence":
        return ASTInstrSequence(
            self.id, [i.transform_instr_subx(usedefs_e) for i in self.instructions])

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTInstrSequence":
        result: List["ASTInstruction"] = []
        return ASTInstrSequence(
            self.id,
            [i.reduce(mapping, live_x) for i in self.instructions if i.is_live(live_x)])

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [i.id for i in self.instructions]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        for i in self.instructions:
            result.extend(i.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        lines: List[str] = []
        for i in self.instructions:
            cinstr = i.to_c_like(sp)
            if len(cinstr) > 0:
                lines.append(cinstr)
        return "\n".join(lines)

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        lines.append(
            "\n".join((i.to_string(sp)) for i in self.instructions))
        return "\n".join(lines)

    def __str__(self) -> str:
        return "\n".join(str(i) for i in self.instructions)


class ASTBranch(ASTStmt):

    def __init__(
            self,
            id: int,
            cond: "ASTExpr",
            ifstmt: "ASTStmt",
            elsestmt: "ASTStmt") -> None:
        ASTStmt.__init__(self, id, "if")
        self._cond = cond
        self._ifstmt = ifstmt
        self._elsestmt = elsestmt

    @property
    def ifstmt(self) -> "ASTStmt":
        return self._ifstmt

    @property
    def elsestmt(self) -> "ASTStmt":
        return self._elsestmt

    @property
    def condition(self) -> "ASTExpr":
        return self._cond

    def is_empty(self) -> bool:
        return self.ifstmt.is_empty() and self.elsestmt.is_empty()

    def address_taken(self) -> Set[str]:
        return self.ifstmt.address_taken().union(
            self.elsestmt.address_taken()).union(self.condition.address_taken())

    def variables_used(self) -> Set[str]:
        return self.ifstmt.variables_used().union(
            self.elsestmt.variables_used()).union(self.condition.variables_used())

    def callees(self) -> Set[str]:
        return self.ifstmt.callees().union(self.elsestmt.callees())

    def live_e(self, live_x: Set[str], result: Dict[int, Set[str]]) -> Set[str]:
        iflive_e = self.ifstmt.live_e(live_x, result)
        elselive_e = self.elsestmt.live_e(live_x, result)
        condlive_e = self.condition.use()
        itelive_e = iflive_e.union(elselive_e).union(condlive_e)
        result[self.id] = live_x
        return itelive_e

    def usedefs_x(
            self,
            usedefs_e: Dict[str, List[Tuple[int, "ASTExpr"]]],
            addresstaken: Set[str],
            node_usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> Dict[
                str, List[Tuple[int, "ASTExpr"]]]:
        node_usedefs_e[self.id] = usedefs_e
        usedefs: Dict[str, List[Tuple[int, "ASTExpr"]]] = copy.deepcopy(usedefs_e)
        ifusedefs = self.ifstmt.usedefs_x(usedefs_e, addresstaken, node_usedefs_e)
        elseusedefs = self.elsestmt.usedefs_x(usedefs_e, addresstaken, node_usedefs_e)
        usedefs = UA.join_usedefs([ifusedefs, elseusedefs])
        return usedefs

    def transform_instr_subx(
            self, usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> "ASTBranch":
        xform_if = self.ifstmt.transform_instr_subx(usedefs_e)
        xform_else = self.elsestmt.transform_instr_subx(usedefs_e)
        xform_cond = self.condition.transform_subx(usedefs_e[self.id])
        return ASTBranch(self.id, xform_cond, xform_if, xform_else)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTBranch":
        r_if = self.ifstmt.reduce(mapping, live_x)
        r_else = self.elsestmt.reduce(mapping, live_x)
        r_cond = self.condition.reduce(mapping, live_x)
        return ASTBranch(self.id, r_cond, r_if, r_else)
        
    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [self.condition.id, self.ifstmt.id, self.elsestmt.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.condition.serialize())
        result.extend(self.ifstmt.serialize())
        result.extend(self.elsestmt.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        lines: List[str] = []
        indent = " " * sp
        lines.append(indent + "if (" + self.condition.to_c_like() + "){")
        lines.append(self.ifstmt.to_c_like(sp + c_indent))
        if not self.elsestmt.is_empty():
            lines.append(indent + "} else {")
            lines.append(self.elsestmt.to_c_like(sp + c_indent))
        lines.append(indent + "}")
        return "\n".join(lines)

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        lines.append(self.condition.to_string(sp + 2))
        lines.append(self.ifstmt.to_string(sp + 2))
        lines.append(self.elsestmt.to_string(sp + 2))
        return "\n".join(lines)


class ASTInstruction(ASTNode, ABC):

    def __init__(self, id: int, tag: str) -> None:
        ASTNode.__init__(self, id, tag)

    @abstractmethod
    def define(self) -> str:
        ...

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])

    def callees(self) -> Set[str]:
        return set([])

    @abstractmethod
    def live_e(self, live_x: Set[str], result: Dict[int, Set[str]]) -> Set[str]:
        ...

    @abstractmethod
    def usedefs_x(
            self,
            usedefs_e: Dict[str, List[Tuple[int, "ASTExpr"]]],
            addresstaken: Set[str],
            node_usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> Dict[
                str, List[Tuple[int, "ASTExpr"]]]:
        ...

    def transform_instr_subx(
            self,
            usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> "ASTInstruction":
        return self

    def is_live(self, live_x: Mapping[int, Set[str]] = {}) -> bool:
        return True

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTInstruction":
        return self

    def use(self) -> List[str]:
        return []


class ASTAssign(ASTInstruction):

    def __init__(self, id: int, lhs: "ASTLval", rhs: "ASTExpr") -> None:
        ASTInstruction.__init__(self, id, "assign")
        self._lhs = lhs
        self._rhs = rhs

    @property
    def lhs(self) -> "ASTLval":
        return self._lhs

    @property
    def rhs(self) -> "ASTExpr":
        return self._rhs

    def address_taken(self) -> Set[str]:
        return self.lhs.address_taken().union(self.rhs.address_taken())

    def variables_used(self) -> Set[str]:
        return self.lhs.variables_used().union(self.rhs.variables_used())

    def callees(self) -> Set[str]:
        return set([])

    def define(self) -> str:
        return str(self.lhs)

    def use(self) -> List[str]:
        return self.rhs.use()

    def kill(self) -> List[str]:
        return [self.define()]

    def live_e(self, live_x: Set[str], result: Dict[int, Set[str]]) -> Set[str]:
        live_e: Set[str] = set([])
        if self.define() not in live_x:
            result[self.id] = live_x
            return live_x
        kill = self.kill()
        for v in live_x:
            if v not in kill:
                live_e.add(v)
        for v in self.use():
            live_e.add(v)
        result[self.id] = live_x
        return live_e

    def usedefs_x(
            self,
            usedefs_e: Dict[str, List[Tuple[int, "ASTExpr"]]],
            addresstaken: Set[str],
            node_usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> Dict[
                str, List[Tuple[int, "ASTExpr"]]]:
        node_usedefs_e[self.id] = usedefs_e
        return UA.update_usedef_assign(usedefs_e, self.id, self.define(), self.rhs)

    def transform_instr_subx(
            self, usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> "ASTAssign":
        if self.id in usedefs_e:
            xform_lhs = self.lhs.transform_subx(usedefs_e[self.id])
            xform_rhs = self.rhs.transform_subx(usedefs_e[self.id])
            return ASTAssign(self.id, xform_lhs, xform_rhs)
        else:
            return self

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTAssign":
        r_lhs = self.lhs.reduce(mapping, live_x)
        r_rhs = self.rhs.reduce(mapping, live_x)
        return ASTAssign(self.id, r_lhs, r_rhs)

    def is_live(self, live_x: Mapping[int, Set[str]] = {}) -> bool:
        if self.lhs.to_c_like() == self.rhs.to_c_like():
            return False
        elif self.id in live_x:
            return str(self.lhs) in live_x[self.id]
        else:
            return True

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [self.lhs.id, self.rhs.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.lhs.serialize())
        result.extend(self.rhs.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        default = (
            (" " * sp)
            + self.lhs.to_c_like()
            + " = "
            + self.rhs.to_c_like()
            + ";  // ("
            + str(self.id)
            + ")")
        return default

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        lines.append(self.lhs.to_string(sp + 2))
        lines.append(self.rhs.to_string(sp + 2))
        return "\n".join(lines)                     

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append(ASTNode.__str__(self))
        lines.append("  " + str(self.lhs))
        lines.append("  " + str(self.rhs))
        return "\n".join(lines)


class ASTCall(ASTInstruction):

    def __init__(
            self,
            id: int,
            lhs: "ASTLval",
            tgt: "ASTExpr",
            args: List["ASTExpr"]) -> None:
        ASTInstruction.__init__(self, id, "call")
        self._lhs = lhs
        self._tgt = tgt
        self._args = args

    @property
    def lhs(self) -> "ASTLval":
        return self._lhs

    @property
    def tgt(self) -> "ASTExpr":
        return self._tgt

    @property
    def arguments(self) -> List["ASTExpr"]:
        return self._args

    def address_taken(self) -> Set[str]:
        return self.tgt.address_taken().union(
            *(a.address_taken() for a in self.arguments))

    def variables_used(self) -> Set[str]:
        return self.lhs.variables_used().union(
            self.tgt.variables_used()).union(
                *(a.variables_used() for a in self.arguments))

    def callees(self) -> Set[str]:
        return set([str(self.tgt)])

    def define(self) -> str:
        return str(self.lhs)

    def use(self) -> List[str]:
        result = []
        result.extend(self.tgt.use())
        for a in self.arguments:
            result.extend(a.use())
        return result

    def kill(self) -> List[str]:
        return ["R0", "R1", "R2", "R3"]

    def live_e(self, live_x: Set[str], result: Dict[int, Set[str]]) -> Set[str]:
        live_e: Set[str] = set([])
        kill = self.kill()
        for v in live_x:
            if v not in kill:
                live_e.add(v)
        for a in self.arguments:
            for v in a.use():
                live_e.add(v)
        result[self.id] = live_x
        return live_e

    def transform_instr_subx(
            self,
            usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> "ASTCall":
        if self.id in usedefs_e:
            xform_args = [a.transform_subx(usedefs_e[self.id]) for a in self.arguments]
            return ASTCall(self.id, self.lhs, self.tgt, xform_args)
        else:
            return self

    def usedefs_x(
            self,
            usedefs_e: Dict[str, List[Tuple[int, "ASTExpr"]]],
            addresstaken: Set[str],
            node_usedefs_e: Dict[int, Dict[str, List[Tuple[int, "ASTExpr"]]]]) -> Dict[
                str, List[Tuple[int, "ASTExpr"]]]:
        node_usedefs_e[self.id] = usedefs_e
        kill = self.kill() + list(addresstaken)
        return UA.update_usedef_call(usedefs_e, kill)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTCall":
        r_args = [a.reduce(mapping, live_x) for a in self.arguments]
        r_lhs = self.lhs.reduce(mapping, live_x)
        return ASTCall(self.id, r_lhs, self.tgt, r_args)
    
    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [
            self.lhs.id,
            self.tgt.id,
            *(a.id for a in self.arguments)]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        if self.lhs != -1:
            result.extend(self.lhs.serialize())
        result.extend(self.tgt.serialize())
        for a in self.arguments:
            result.extend(a.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        indent = " " * sp
        calltgt = (
            self.tgt.to_c_like()
            + "("
            + ", ".join(str(a.to_c_like()) for a in self.arguments)
            + ");  // ("
            + str(self.id)
            + ")")
        if self.lhs.id == -1:        
            return indent + calltgt
        else:
            return indent + self.lhs.to_c_like() + " = " + calltgt

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        if self.lhs.id != -1:
            lines.append(self.lhs.to_string(sp + 2))
        lines.append(self.tgt.to_string(sp + 2))
        for a in self.arguments:
            lines.append(a.to_string(sp + 2))
        return "\n".join(lines)

    def __str__(self) -> str:
        lines: List[str] = []
        lhs = "  void return" if self.lhs.id == -1 else "  " + str(self.lhs)
        lines.append(ASTNode.__str__(self))
        lines.append(lhs)
        lines.append("  " + str(self.tgt))
        lines.append("  " + "\n  ".join(str(a) for a in self.arguments))
        return "\n".join(lines)


class ASTLval(ASTNode):

    def __init__(self, id: int, lhost: "ASTLHost", offset: "ASTOffset") -> None:
        ASTNode.__init__(self, id, "lval")
        self._lhost = lhost
        self._offset = offset

    @property
    def lhost(self) -> "ASTLHost":
        return self._lhost

    @property
    def offset(self) -> "ASTOffset":
        return self._offset

    def address_taken(self) -> Set[str]:
        return self.lhost.address_taken().union(self.offset.address_taken())

    def variables_used(self) -> Set[str]:
        return self.lhost.variables_used().union(self.offset.variables_used())

    def offset_to_string(self, sp: int = 0) -> str:
        if self.offset.id == -1:
            return ""
        else:
            return self.offset.to_string(sp)

    def use(self) -> List[str]:
        return self.lhost.use() + self.offset.use()

    def transform_subx(
            self, usedefs_e: Dict[str, List[Tuple[int, "ASTExpr"]]]) -> "ASTLval":
        return self

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTLval":
        r_lhost = self.lhost.reduce(mapping, live_x)
        r_offset = self.offset.reduce(mapping, live_x)
        return ASTLval(self.id, r_lhost, r_offset)

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [self.lhost.id, self.offset.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        if self.lhost.id == -1 and self.offset.id == -1:
            return []
        else:
            result: List[ASTNodeRecord] = []
            result.append(self.noderecord())
            if self.offset.id != -1:
                result.extend(self.offset.serialize())
            result.extend(self.lhost.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        if self.offset.id == -1:
            return self.lhost.to_c_like()
        else:
            return self.lhost.to_c_like() + self.offset.to_c_like()

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        lines.append(self.lhost.to_string(sp + 2))
        if self.offset.id != -1:
            lines.append(self.offset_to_string(sp + 2))
        return "\n".join(lines)                     

    def __str__(self) -> str:
        return str(self.lhost) + self.offset_to_string()


class ASTLHost(ASTNode):

    def __init__(self, id: int, tag: str) -> None:
        ASTNode.__init__(self, id, tag)

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])

    def transform_subx(
            self, usedefs: Dict[str, List[Tuple[int, "ASTExpr"]]]) -> "ASTLHost":
        return self

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTLHost":
        return self


class ASTVarInfo(ASTNode):

    def __init__(
            self,
            id: int,
            vname: str,
            vtype: "ASTVType" = ASTTNamed(-1, "unknown"),
            altname: Optional[str] = None) -> None:
        ASTNode.__init__(self, id, "varinfo")
        self._vname = vname
        self._vtype = vtype
        self._altname = altname

    @property
    def vname(self) -> str:
        return self._vname

    @property
    def vtype(self) -> "ASTVType":
        return self._vtype        

    @property
    def altname(self) -> Optional[str]:
        return self._altname

    @property
    def displayname(self) -> str:
        if self.altname:
            return self.altname
        else:
            return self.vname

    @property
    def is_function(self) -> bool:
        return self.vtype.is_function_type

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["vname"] = self.vname
        if self.altname:
            result["altname"] = self.altname
        result["args"] = [self.vtype.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.vtype.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        if self.is_function:
            vty = cast("ASTTFun", self.vtype)
            return (
                vty.returntype.to_c_like(sp)
                + " "
                + self.vname
                + "("
                + ", ".join(a.to_c_like(sp) + " " + n for (n, a) in vty.argtypes)
                + ")")
        else:
            return self.vtype.to_c_like(sp) + " " + self.displayname

    def __str__(self) -> str:
        if self.altname:
            return self.altname
        else:
            return self.vname


class ASTVariable(ASTLHost):

    def __init__(
            self,
            id: int,
            varinfo: ASTVarInfo) -> None:
        ASTLHost.__init__(self, id, "var")
        self._varinfo = varinfo

    @property
    def varinfo(self) -> ASTVarInfo:
        return self._varinfo

    @property
    def vname(self) -> str:
        return self.varinfo.vname

    @property
    def displayname(self) -> str:
        if self.varinfo.altname:
            return self.varinfo.altname
        else:
            return self.vname

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([self.vname])

    def use(self) -> List[str]:
        if self.vname == "PC":
            return []
        else:
            return [self.vname]

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [self.varinfo.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        if self.id == -1:
            return []
        else:
            return [self.noderecord()]

    def to_c_like(self, sp: int = 0) -> str:
        return self.displayname

    def to_string(self, sp: int = 0) -> str:
        return ASTNode.to_string(self, sp) + "(" + self.vname + ")"

    def __str__(self):
        return self.vname


class ASTMemRef(ASTLHost):

    def __init__(
            self,
            id: int,
            memexp: "ASTExpr") -> None:
        ASTLHost.__init__(self, id, "memref")
        self._memexp = memexp

    @property
    def memexp(self) -> "ASTExpr":
        return self._memexp

    def address_taken(self) -> Set[str]:
        return self.memexp.address_taken()

    def variables_used(self) -> Set[str]:
        return self.memexp.variables_used()

    def use(self) -> List[str]:
        return self.memexp.use()

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [self.memexp.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.memexp.serialize())
        return result

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTMemRef":
        r_memexp = self.memexp.reduce(mapping, live_x)
        return ASTMemRef(self.id, r_memexp)

    def to_c_like(self, sp: int = 0) -> str:
        return "*(" + self.memexp.to_c_like() + ")"

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        lines.append(self.memexp.to_string(sp + 2))
        return "\n".join(lines)

    def __str__(self):
        return "*(" + str(self.memexp) + ")"


class ASTOffset(ASTNode):

    def __init__(self, id: int, tag: str) -> None:
        ASTNode.__init__(self, id, tag)

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTOffset":
        return self


class ASTNoOffset(ASTOffset):

    def __init__(self, id: int) -> None:
        ASTOffset.__init__(self, id, "no-offset")

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])

    def __str__(self) -> str:
        return ""


class ASTFieldOffset(ASTOffset):

    def __init__(self, id: int, fieldname: str, offset: "ASTOffset") -> None:
        ASTOffset.__init__(self, id, "field-offset")
        self._fieldname = fieldname
        self._offset = offset

    @property
    def fieldname(self) -> str:
        return self._fieldname

    @property
    def offset(self) -> "ASTOffset":
        return self._offset

    def address_taken(self) -> Set[str]:
        return self.offset.address_taken()

    def variables_used(self) -> Set[str]:
        return self.offset.variables_used()

    def use(self) -> List[str]:
        return self.offset.use()

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTFieldOffset":
        r_offset = self.offset.reduce(mapping, live_x)
        return ASTFieldOffset(self.id, self.fieldname, r_offset)

    def __str__(self) -> str:
        return "." + self.fieldname + str(self.offset)


class ASTIndexOffset(ASTOffset):

    def __init__(self, id: int, index: "ASTExpr", offset: "ASTOffset") -> None:
        ASTOffset.__init__(self, id, "index-offset")
        self._index = index
        self._offset = offset

    @property
    def index(self) -> "ASTExpr":
        return self._index

    @property
    def offset(self) -> "ASTOffset":
        return self._offset

    def address_taken(self) -> Set[str]:
        return self.index.address_taken().union(self.offset.address_taken())

    def variables_used(self) -> Set[str]:
        return self.index.variables_used().union(self.variables_used())

    def use(self) -> List[str]:
        return self.index.use() + self.offset.use()

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTIndexOffset":
        r_index = self.index.reduce(mapping, live_x)
        r_offset = self.offset.reduce(mapping, live_x)
        return ASTIndexOffset(self.id, r_index, r_offset)

    def __str__(self) -> str:
        return "[" + str(self.index) + "]" + str(self.offset)


class ASTExpr(ASTNode):

    def __init__(self, id: int, tag: str) -> None:
        ASTNode.__init__(self, id, tag)

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])

    def transform_subx(self, usedefs: Dict[str, List[Tuple[int, "ASTExpr"]]]) -> "ASTExpr":
        return self

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTExpr":
        return self


class ASTConstant(ASTExpr):

    def __init__(self, id: int, tag: str) -> None:
        ASTExpr.__init__(self, id, tag)

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])


class ASTIntegerConstant(ASTConstant):

    def __init__(self, id: int, cvalue: int) -> None:
        ASTConstant.__init__(self, id, "integer-constant")
        self._cvalue = cvalue

    @property
    def cvalue(self) -> int:
        return self._cvalue

    def use(self) -> List[str]:
        return []

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["value"] = str(self.cvalue)
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        return [self.noderecord()]

    def to_c_like(self, sp: int = 0) -> str:
        return str(self.cvalue)

    def to_string(self, sp: int = 0) -> str:
        return ASTNode.to_string(self, sp) + "(" + str(self.cvalue) + ")"

    def __str__(self) -> str:
        return str(self.cvalue)


class ASTStringConstant(ASTConstant):

    def __init__(self, id: int, expr: "ASTExpr", cstr: str, saddr: str) -> None:
        ASTConstant.__init__(self, id, "string-constant")
        self._expr = expr    # expression that produced the string
        self._cstr = cstr
        self._saddr = saddr

    @property
    def expr(self) -> "ASTExpr":
        return self._expr
    
    @property
    def cstr(self) -> str:
        return self._cstr

    @property
    def string_address(self) -> str:
        return self._saddr

    def use(self) -> List[str]:
        return []
        # return self.expr.use()

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["cstr"] = self.cstr
        result["va"] = self.string_address
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        return [self.noderecord()]

    def to_c_like(self, sp: int = 0) -> str:
        return '"' + self.cstr + '"'

    def to_string(self, sp: int = 0) -> str:
        return ASTNode.to_string(self, sp) + "(" + self.cstr + ")"

    def __str__(self) -> str:
        return '"' + self.cstr + '"'


class ASTLvalExpr(ASTExpr):

    def __init__(self, id: int, lval: "ASTLval", tag: str = "lval-expr") -> None:
        ASTExpr.__init__(self, id, tag)
        self._lval = lval

    @property
    def lval(self) -> "ASTLval":
        return self._lval

    def address_taken(self) -> Set[str]:
        return self.lval.address_taken()

    def variables_used(self) -> Set[str]:
        return self.lval.variables_used()

    def use(self) -> List[str]:
        return self.lval.use()

    def transform_subx(
            self, usedefs_e: Dict[str, List[Tuple[int, "ASTExpr"]]]) -> "ASTExpr":
        name = str(self.lval)
        if name in usedefs_e and len(usedefs_e[name]) == 1:
            (assign_id, expr) = usedefs_e[name][0]
            return ASTSubstitutedExpr(self.id, self.lval, assign_id, expr)
        else:
            return self

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTExpr":
        r_lval = self.lval.reduce(mapping, live_x)
        return ASTLvalExpr(self.id, r_lval)

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [self.lval.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.lval.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        return self.lval.to_c_like()

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        lines.append(self.lval.to_string(sp + 2))
        return "\n".join(lines)

    def __str__(self) -> str:
        return str(self.lval)


class ASTSubstitutedExpr(ASTLvalExpr):

    def __init__(self, id: int, lval: "ASTLval", assign_id: int, expr: "ASTExpr") -> None:
        ASTLvalExpr.__init__(self, id, lval, tag = "substituted-expr")
        self._assign_id = assign_id
        self._expr = expr

    @property
    def assign_id(self) -> int:
        return self._assign_id

    @property
    def substituted_expr(self) -> "ASTExpr":
        return self._expr

    def use(self) -> List[str]:
        return self.substituted_expr.use()

    def transform_subx(
            self, usedefs_e: Dict[str, List[Tuple[int, "ASTExpr"]]]) -> "ASTExpr":
        xform_exp = self.substituted_expr.transform_subx(usedefs_e)
        return ASTSubstitutedExpr(self.id, self.lval, self.assign_id, xform_exp)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTExpr":
        # mapping[self.id] = self.substituted_expr.id
        r_lval = self.lval.reduce(mapping, live_x)
        r_substituted_expr = self.substituted_expr.reduce(mapping, live_x)
        return ASTSubstitutedExpr(self.id, r_lval, self.assign_id, r_substituted_expr)

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["assigned"] = self.assign_id
        result["args"] = [self.lval.id, self.substituted_expr.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.lval.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        return self.substituted_expr.to_c_like()

    
class ASTUnaryOp(ASTExpr):

    def __init__(self, id: int, op: str,  exp: "ASTExpr") -> None:
        ASTExpr.__init__(self, id, "unary-op")
        self._op = op
        self._exp = exp

    @property
    def op(self) -> str:
        return self._op

    @property
    def exp(self) -> "ASTExpr":
        return self._exp

    def address_taken(self) -> Set[str]:
        return self.exp.address_taken()

    def variables_used(self) -> Set[str]:
        return self.exp.variables_used()

    def use(self) -> List[str]:
        return self.exp.use()

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["op"] = self.op
        result["args"] = [self.exp.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.exp.serialize())
        return result

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTUnaryOp":
        return ASTUnaryOp(self.id, self.op, self.exp.reduce(mapping, live_x))

    def to_c_like(self, sp: int = 0) -> str:
        return operators[self.op] + self.exp.to_c_like()

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        lines.append(self.exp.to_string(sp + 2))
        return "\n".join(lines)

    def __str__(self) -> str:
        return "(" + operators[self.op] + str(self.exp) + ")"


class ASTBinaryOp(ASTExpr):

    def __init__(
            self,
            id: int,
            op: str,
            exp1: "ASTExpr",
            exp2: "ASTExpr") -> None:
        ASTExpr.__init__(self, id, "binary-op")
        self._op = op
        self._exp1 = exp1
        self._exp2 = exp2

    @property
    def op(self) -> str:
        return self._op

    @property
    def exp1(self) -> "ASTExpr":
        return self._exp1

    @property
    def exp2(self) -> "ASTExpr":
        return self._exp2

    def address_taken(self) -> Set[str]:
        return self.exp1.address_taken().union(self.exp2.address_taken())

    def variables_used(self) -> Set[str]:
        return self.exp1.variables_used().union(self.exp2.variables_used())

    def use(self) -> List[str]:
        return self.exp1.use() + self.exp2.use()

    def transform_subx(
            self, usedefs_e: Dict[str, List[Tuple[int, "ASTExpr"]]]) -> "ASTBinaryOp":
        xform_exp1 = self.exp1.transform_subx(usedefs_e)
        xform_exp2 = self.exp2.transform_subx(usedefs_e)
        return ASTBinaryOp(self.id, self.op, xform_exp1, xform_exp2)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTBinaryOp":
        r_exp1 = self.exp1.reduce(mapping, live_x)
        r_exp2 = self.exp2.reduce(mapping, live_x)
        return ASTBinaryOp(self.id, self.op, r_exp1, r_exp2)

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["op"] = self.op
        result["args"] = [self.exp1.id, self.exp2.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.exp1.serialize())
        result.extend(self.exp2.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        return self.exp1.to_c_like() + operators[self.op] + self.exp2.to_c_like()

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp) + ":" + self.op)
        lines.append(self.exp1.to_string(sp + 2))
        lines.append(self.exp2.to_string(sp + 2))
        return "\n".join(lines)

    def __str__(self) -> str:
        return "(" + str(self.exp1) + operators[self.op] + str(self.exp2) + ")"


class ASTAddressOf(ASTExpr):

    def __init__(self, id: int, lval: "ASTLval") -> None:
        ASTExpr.__init__(self, id, "address-of")
        self._lval = lval

    @property
    def lval(self) -> "ASTLval":
        return self._lval

    def address_taken(self) -> Set[str]:
        return set([str(self.lval)])

    def variables_used(self) -> Set[str]:
        return set([str(self.lval)])

    def use(self) -> List[str]:
        return []

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {}) -> "ASTAddressOf":
        return self

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        lines.append(self.lval.to_string(sp + 2))
        return "\n".join(lines)

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [self.lval.id]
        return result

    def to_c_like(self, sp: int = 0) -> str:
        return "&" + self.lval.to_c_like()

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.lval.serialize())
        return result

    def __str__(self) -> str:
        return "&(" + str(self.lval) + ")"
    
