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
"""Node in abstract syntax tree.

Grammar (based on CIL (ref https://people.eecs.berkeley.edu/~necula/cil/))

file: global list

global: GVarDecl varinfo
      | GVar varinfo
      | GFun fundec
      | GType typeinfo

fundec: varinfo (varinfo list) (varinfo list) block

typeinfo: string typ

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
   | TFloat <fkind>
   | TPtr typ
   | TArray typ exp option
   | TFun typ (string * typ) list
   | TNamed string
   | TCompInfo compinfo
   | TEnum enuminfo

ikind: IChar
       ISChar
       IUChar
       IBool
       IInt
       IUInt
       IShort
       IUShort
       ILong
       IULong
       ILongLong
       IULongLong

fkind: FFloat
       FDouble
       FLongDouble

compinfo: bool string (fieldinfo list)

fieldinfo: name typ

enuminfo: name (string * exp) list ikind

varinfo: string typ storage

storage: NoStorage
       | Static
       | Register
       | Extern

"""
import copy

from abc import ABC, abstractmethod
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
    Set,
    Tuple,
    TYPE_CHECKING,
    Union)

from chb.app.ASTUtil import InstrUseDef, UseDef, get_arg_loc

if TYPE_CHECKING:
    from chb.bctypes.BCTyp import BCTyp, BCTypFun, BCTypArray, BCTypComp


ASTNodeRecord = NewType(
    "ASTNodeRecord", Dict[str, Union[List[str], List[int], int, str]])


c_indent = 3


operators = {
    "and": " && ",   # logical and
    "bor": " | ",    # bitwise or
    "bxor": " ^ ",   # bitwise xor
    "asr": " >> ",   # arithmetic shift right; need to infer type as signed
    "band": " & ",   # bitwise and
    "div": " / ",    # integer division
    "eq": " == ",
    "ge": " >= ",
    "gt": " > ",
    "land": " && ",
    "le": " <= ",
    "lnot": " ! ",
    "lor": " || ",   # logical or
    "lsl": " << ",   # logical shift left
    "lsr": " >> ",   # logical shift right; need to infer type as unsigned
    "lt": " < ",
    "mod": " % ", 
    "shiftlt": " << ",
    "shiftrt": " >> ",
    "minus": " - ",
    "mult": " * ",   # multiplication
    "ne": " != ",
    "plus": " + "
    }


inttypes = {
    "ichar": "char",
    "ischar": "signed char",
    "iuchar": "unsigned char",
    "ibool": "bool",
    "iint": "int",
    "iuint": "unsigned int",
    "ishort": "short",
    "iushort": "unsigned short",
    "ilong": "long",
    "iulong": "unsigned long",
    "ilonglong": "long long",
    "iulonglong": "unsigned long long"
}


floattypes = {
    "float": "float",
    "fdouble": "double",
    "flongdouble": "long double"
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

    @property
    def is_ast_stmt(self) -> bool:
        return False

    @property
    def is_ast_lval(self) -> bool:
        return False

    @property
    def is_ast_expr(self) -> bool:
        return False

    @property
    def is_ast_offset(self) -> bool:
        return False

    @property
    def is_ast_lhost(self) -> bool:
        return False

    @property
    def is_ast_instruction(self) -> bool:
        return False

    def transform_instr_subx(
            self,
            usedefs_e: InstrUseDef) -> "ASTNode":
        return self

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTNode":
        return self

    def defs(self) -> List[Tuple[int, str]]:
        """Return list of (instr-id (assign or call), variable) pairs."""

        return []

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

    def structure_to_string(self, sp: int = 0) -> str:
        return (" " * sp) + str(self.id) + ":" + self.tag

    def __str__(self) -> str:
        return str(self.id) + ":" + self.tag


class ASTStmt(ASTNode):

    def __init__(self, id: int, tag: str) -> None:
        ASTNode.__init__(self, id, tag)

    @property
    def is_ast_stmt(self) -> bool:
        return True

    @property
    def is_ast_return(self) -> bool:
        return False

    @property
    def is_ast_block(self) -> bool:
        return False

    @property
    def is_ast_branch(self) -> bool:
        return False

    @property
    def is_ast_instruction_sequence(self) -> bool:
        return False

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
            usedefs_e: UseDef,
            addresstaken: Set[str],
            node_usedefs_e: InstrUseDef) -> UseDef:
        """Return the reaching definitions of variables that may be substituted.

        usedefs_e: the reaching definitions at node entry
                   Var -> (Label * expr)
        addresstaken: set of variables whose address is taken
        node_usedefs_e: mapping from instruction nodes to reaching definitions
                        Label -> Var -> (Label * expr)
        """
        ...

    def transform_instr_subx(self, usedefs_e: InstrUseDef) -> "ASTStmt":
        return self

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTStmt":
        return self

    def variables_used(self) -> Set[str]:
        return set([])

    def callees(self) -> Set[str]:
        return set([])

    def structure_to_string(self, sp: int = 0) -> str:
        return (" " * sp) + self.tag


class ASTReturn(ASTStmt):

    def __init__(self, id: int, expr: Optional["ASTExpr"]) -> None:
        ASTStmt.__init__(self, id, "return")
        self._expr = expr

    @property
    def is_ast_return(self) -> bool:
        return True

    @property
    def expr(self) -> "ASTExpr":
        if self._expr is not None:
            return self._expr
        else:
            raise Exception("Function does not return a value")

    def has_return_value(self) -> bool:
        return self._expr is not None

    def address_taken(self) -> Set[str]:
        if self.has_return_value():
            return self.expr.address_taken()
        else:
            return set([])

    def defs(self) -> List[Tuple[int, str]]:
        return []

    def variables_used(self) -> Set[str]:
        if self.has_return_value():
            return self.expr.variables_used()
        else:
            return set([])

    def live_e(self, live_x: Set[str], result: Dict[int, Set[str]]) -> Set[str]:
        result[self.id] = live_x
        if self.has_return_value():
            return set(self.expr.use())
        else:
            return set([])

    def usedefs_x(
            self,
            usedefs_e: UseDef,
            addresstaken: Set[str],
            node_usedefs_e: InstrUseDef) -> UseDef:
        node_usedefs_e.set(self.id, usedefs_e)
        if self.has_return_value():
            node_usedefs_e.set(self.id, usedefs_e)
        return UseDef({})

    def transform_instr_subx(self, usedefs_e: InstrUseDef) -> "ASTReturn":
        if self.has_return_value():
            xexpr: Optional["ASTExpr"] = self.expr.transform_subx(
                usedefs_e.get(self.id))
        else:
            xexpr = None
        return ASTReturn(self.id, xexpr)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTReturn":
        if self.has_return_value():
            r_expr: Optional["ASTExpr"] = self.expr.reduce(mapping, live_x, macronames)
        else:
            r_expr = None
        return ASTReturn(self.id, r_expr)

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        if self.has_return_value():
            result["args"] = [self.expr.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        if self.has_return_value():
            result.extend(self.expr.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        indent = " " * sp
        if self.has_return_value():
            return (indent + "return " + self.expr.to_c_like() + ";")
        else:
            return (indent + "return;")

    def structure_to_string(self, sp: int = 0) -> str:
        return (" " * sp) + "Return"

    def to_string(self, sp: int = 0) -> str:
        return self.to_c_like(sp)


class ASTBlock(ASTStmt):

    def __init__(self, id: int, stmts: List["ASTStmt"]) -> None:
        ASTStmt.__init__(self, id, "block")
        self._stmts = stmts

    @property
    def is_ast_block(self) -> bool:
        return True

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

    def defs(self) -> List[Tuple[int, str]]:
        result: List[Tuple[int, str]] = []
        for s in self.stmts:
            result.extend(s.defs())
        return result

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
            usedefs_e: UseDef,
            addresstaken: Set[str],
            node_usedefs_e: InstrUseDef) -> UseDef:
        usedefs = usedefs_e
        for s in self.stmts:
            usedefs = s.usedefs_x(usedefs, addresstaken, node_usedefs_e)
        return usedefs

    def transform_instr_subx(self, usedefs_e: InstrUseDef) -> "ASTBlock":
        return ASTBlock(
            self.id,
            [s.transform_instr_subx(usedefs_e) for s in self.stmts])

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTBlock":
        return ASTBlock(
            self.id, [s.reduce(mapping, live_x, macronames) for s in self.stmts])

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

    def structure_to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append("  Block-" + str(sp) + ":")
        lines.append((" " * sp) + str(sp) + "{")
        for s in self.stmts:
            lines.append(s.structure_to_string(sp + 2))
        lines.append((" " * sp) + str(sp) + "}")
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
    def is_ast_instruction_sequence(self) -> bool:
        return True

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

    def defs(self) -> List[Tuple[int, str]]:
        result: List[Tuple[int, str]] = []
        for instr in self.instructions:
            result.extend(instr.defs())
        return result

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
            usedefs_e: UseDef,
            addresstaken: Set[str],
            node_usedefs_e: InstrUseDef) -> UseDef:
        usedefs = usedefs_e
        for i in self.instructions:
            usedefs = i.usedefs_x(usedefs, addresstaken, node_usedefs_e)
        return usedefs

    def transform_instr_subx(self, usedefs_e: InstrUseDef) -> "ASTInstrSequence":
        return ASTInstrSequence(
            self.id,
            [i.transform_instr_subx(usedefs_e) for i in self.instructions])

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTInstrSequence":
        result: List["ASTInstruction"] = []
        return ASTInstrSequence(
            self.id,
            [i.reduce(mapping, live_x, macronames)
             for i in self.instructions if i.is_live(live_x)])

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
            elsestmt: "ASTStmt",
            relative_offset: int) -> None:
        ASTStmt.__init__(self, id, "if")
        self._cond = cond
        self._ifstmt = ifstmt
        self._elsestmt = elsestmt
        self._relative_offset = relative_offset

    @property
    def is_ast_branch(self) -> bool:
        return True

    @property
    def ifstmt(self) -> "ASTStmt":
        return self._ifstmt

    @property
    def elsestmt(self) -> "ASTStmt":
        return self._elsestmt

    @property
    def condition(self) -> "ASTExpr":
        return self._cond

    @property
    def relative_offset(self) -> int:
        return self._relative_offset

    def is_empty(self) -> bool:
        return self.ifstmt.is_empty() and self.elsestmt.is_empty()

    def address_taken(self) -> Set[str]:
        return self.ifstmt.address_taken().union(
            self.elsestmt.address_taken()).union(self.condition.address_taken())

    def defs(self) -> List[Tuple[int, str]]:
        return self.ifstmt.defs() + self.elsestmt.defs()

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
            usedefs_e: UseDef,
            addresstaken: Set[str],
            node_usedefs_e: InstrUseDef) -> UseDef:
        node_usedefs_e.set(self.id, usedefs_e)
        node_usedefs_e.set(self.condition.id, usedefs_e)
        ifusedefs = self.ifstmt.usedefs_x(usedefs_e, addresstaken, node_usedefs_e)
        elseusedefs = self.elsestmt.usedefs_x(usedefs_e, addresstaken, node_usedefs_e)
        return ifusedefs.join(elseusedefs)

    def transform_instr_subx(self, usedefs_e: InstrUseDef) -> "ASTBranch":
        xform_if = self.ifstmt.transform_instr_subx(usedefs_e)
        xform_else = self.elsestmt.transform_instr_subx(usedefs_e)
        xform_cond = self.condition.transform_subx(usedefs_e.get(self.id))
        return ASTBranch(self.id, xform_cond, xform_if, xform_else, self.relative_offset)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTBranch":
        r_if = self.ifstmt.reduce(mapping, live_x, macronames)
        r_else = self.elsestmt.reduce(mapping, live_x, macronames)
        r_cond = self.condition.reduce(mapping, live_x, macronames)
        return ASTBranch(self.id, r_cond, r_if, r_else, self.relative_offset)

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["pc-offset"] = self.relative_offset
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
        lines.append(
            indent
            + "if ("
            + self.condition.to_c_like()
            + "){")
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

    def structure_to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        indent = " " * sp
        lines.append(indent + "then-" + str(sp))
        lines.append(indent + ("-" * 40))
        lines.append(indent + self.ifstmt.structure_to_string(sp + 4))
        lines.append(indent + "else-" + str(sp))
        lines.append(indent + ("~" * 40) + str(sp))
        lines.append(indent + self.elsestmt.structure_to_string(sp + 4))
        lines.append(indent + ("=" * 40) + str(sp))
        return "\n".join(lines)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self))
        lines.append("Condition: " + str(self.condition.id))
        lines.append("  Then   : " + str(self.ifstmt.id))
        lines.append("  Else   : " + str(self.elsestmt.id))
        return "\n".join(lines)


class ASTInstruction(ASTNode, ABC):

    def __init__(self, id: int, tag: str) -> None:
        ASTNode.__init__(self, id, tag)

    @property
    def is_ast_instruction(self) -> bool:
        return True

    @property
    def is_ast_assign(self) -> bool:
        return False

    @property
    def is_ast_call(self) -> bool:
        return False

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
            usedefs_e: UseDef,
            addresstaken: Set[str],
            node_usedefs_e: InstrUseDef) -> UseDef:
        ...

    def transform_instr_subx(self, usedefs_e: InstrUseDef) -> "ASTInstruction":
        return self

    def is_live(self, live_x: Mapping[int, Set[str]] = {}) -> bool:
        return True

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTInstruction":
        return self

    def use(self) -> List[str]:
        return []


class ASTAssign(ASTInstruction):

    def __init__(self, id: int, lhs: "ASTLval", rhs: "ASTExpr") -> None:
        ASTInstruction.__init__(self, id, "assign")
        self._lhs = lhs
        self._rhs = rhs

    @property
    def is_ast_assign(self) -> bool:
        return True

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

    def defs(self) -> List[Tuple[int, str]]:
        return [(self.id, self.define() + " (" + str(self.rhs) + ")")]

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
        kill = self.kill()
        for v in live_x:
            if v not in kill:
                live_e.add(v)
        for v in self.use():
            live_e.add(v)
        if self.lhs.is_global:
            live_e.add(str(self.lhs))
        result[self.id] = live_x
        return live_e

    def usedefs_x(
            self,
            usedefs_e: UseDef,
            addresstaken: Set[str],
            node_usedefs_e: InstrUseDef) -> UseDef:
        node_usedefs_e.set(self.id, usedefs_e)
        return usedefs_e.apply_assign(self.id, self.define(), self.rhs)

    def transform_instr_subx(self, usedefs_e: InstrUseDef) -> "ASTAssign":
        if usedefs_e.has(self.id):
            xform_lhs = self.lhs.transform_subx(usedefs_e.get(self.id))
            xform_rhs = self.rhs.transform_subx(usedefs_e.get(self.id))
            return ASTAssign(self.id, xform_lhs, xform_rhs)
        else:
            return self

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTAssign":
        r_lhs = self.lhs.reduce(mapping, live_x, macronames)
        r_rhs = self.rhs.reduce(mapping, live_x, macronames)
        return ASTAssign(self.id, r_lhs, r_rhs)

    def is_live(self, live_x: Mapping[int, Set[str]] = {}) -> bool:
        if self.lhs.to_c_like() == self.rhs.to_c_like():
            return False
        elif self.lhs.is_memref:
            return True
        elif self.lhs.is_global:
            return True
        elif self.lhs.has_altname():
            return True
        elif str(self.lhs).startswith("rtn_"):
            return True
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
            + ";"
            + " // " + str(self.id))
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
    def is_ast_call(self) -> bool:
        return True

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

    def defs(self) -> List[Tuple[int, str]]:
        if self.lhs.id == -1:
            return []
        else:
            return [(self.id, str(self.lhs))]

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
        return ["R0", "R1", "R2", "R3", "$v0", "$v1"]

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

    def transform_instr_subx(self, usedefs_e: InstrUseDef) -> "ASTCall":
        if usedefs_e.has(self.id):
            xform_args = [a.transform_subx(usedefs_e.get(self.id)) for a in self.arguments]
            return ASTCall(self.id, self.lhs, self.tgt, xform_args)
        else:
            return self

    def usedefs_x(
            self,
            usedefs_e: UseDef,
            addresstaken: Set[str],
            node_usedefs_e: InstrUseDef) -> UseDef:
        node_usedefs_e.set(self.id, usedefs_e)
        kill = self.kill() + list(addresstaken)
        return usedefs_e.apply_call(kill)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTCall":
        r_args = [a.reduce(mapping, live_x, macronames) for a in self.arguments]
        r_lhs = self.lhs.reduce(mapping, live_x, macronames)
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
        if self.lhs.id != -1:
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
            + ");  // " + str(self.id))
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
    def is_ast_lval(self) -> bool:
        return True

    @property
    def is_ignored(self) -> bool:
        return self.lhost.is_ignored

    @property
    def lhost(self) -> "ASTLHost":
        return self._lhost

    @property
    def offset(self) -> "ASTOffset":
        return self._offset

    @property
    def ctype(self) -> Optional["BCTyp"]:
        if self.offset.is_no_offset:
            return self.lhost.ctype
        else:
            return self.offset.offset_ctype(self.lhost.ctype)

    @property
    def is_memref(self) -> bool:
        return self.lhost.is_memref

    @property
    def is_global(self) -> bool:
        return self.lhost.is_global

    def has_altname(self) -> bool:
        return self.lhost.is_variable and self.lhost.has_altname()

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

    def transform_subx(self, usedefs_e: UseDef) -> "ASTLval":
        xlhost = self.lhost.transform_subx(usedefs_e)
        xoffset = self.offset.transform_subx(usedefs_e)
        return ASTLval(self.id, xlhost, xoffset)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTLval":
        r_lhost = self.lhost.reduce(mapping, live_x, macronames)
        r_offset = self.offset.reduce(mapping, live_x, macronames)
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
        # if self.offset.id == -1:
        #   return self.lhost.to_c_like()
        if self.lhost.is_memref:
            memexp = cast("ASTMemRef", self.lhost).memexp
            if self.offset.is_field_offset:
                fieldname = cast("ASTFieldOffset", self.offset).fieldname
                return memexp.to_c_like() + "->" + str(self.offset)[1:]
            elif self.offset.is_index_offset:
                indexoffset = cast("ASTIndexOffset", self.offset)
                return memexp.to_c_like() + " + " + indexoffset.index.to_c_like()
            else:
                return self.lhost.to_c_like() + self.offset.to_c_like()
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
        return str(self.lhost) + str(self.offset)


class ASTLHost(ASTNode):

    def __init__(self, id: int, tag: str) -> None:
        ASTNode.__init__(self, id, tag)

    @property
    def is_ast_lhost(self) -> bool:
        return True

    @property
    def is_ignored(self) -> bool:
        return False

    @property
    def is_memref(self) -> bool:
        return False

    @property
    def is_variable(self) -> bool:
        return False

    @property
    def is_global(self) -> bool:
        return False

    @property
    def ctype(self) -> Optional["BCTyp"]:
        return None

    def has_altname(self) -> bool:
        return False

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])

    def transform_subx(self, usedefs: UseDef) -> "ASTLHost":
        return self

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTLHost":
        return self


class ASTVarInfo(ASTNode):

    def __init__(
            self,
            id: int,
            vname: str,
            vtype: Optional["BCTyp"],
            altname: Optional[str],
            parameter: Optional[int],
            globaladdress: Optional[int],
            arrayindex: Optional[int] = None) -> None:
        ASTNode.__init__(self, id, "varinfo")
        self._vname = vname
        self._vtype = vtype
        self._altname = altname
        self._parameter = parameter
        self._globaladdress = globaladdress
        self._arrayindex = arrayindex

    @property
    def is_ignored(self) -> bool:
        return self.id == (-1)

    @property
    def vname(self) -> str:
        return self._vname

    @property
    def vtype(self) -> Optional["BCTyp"]:
        return self._vtype

    @property
    def altname(self) -> Optional[str]:
        return self._altname

    @property
    def arrayindex(self) -> Optional[int]:
        """Return the starting array index (for arrays packed into one variable)."""

        return self._arrayindex

    def has_altname(self) -> bool:
        return self.altname is not None

    @property
    def displayname(self) -> str:
        if self.altname:
            return self.altname
        else:
            return self.vname

    @property
    def is_function(self) -> bool:
        if self.vtype:
            return self.vtype.is_function
        else:
            return False

    @property
    def returns_void(self) -> bool:
        if self.is_function:
            vtype = cast("BCTypFun", self.vtype)
            return vtype.returntype.is_void
        else:
            return False

    @property
    def is_struct(self) -> bool:
        if self.vtype:
            return self.vtype.is_struct
        else:
            return False

    @property
    def is_global(self) -> bool:
        return self._globaladdress is not None

    @property
    def is_parameter(self) -> bool:
        return self._parameter is not None

    def has_global_address(self) -> bool:
        return self._globaladdress is not None

    @property
    def global_address(self) -> int:
        if self._globaladdress is not None:
            return self._globaladdress
        else:
            raise Exception(
                "Varinfo " + self.vname + " does not have a global address")

    @property
    def parameter(self) -> int:
        if self._parameter is not None:
            return self._parameter
        else:
            raise Exception("VArinfo " + self.vname + " is not a parameter")

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["vname"] = self.vname
        if self.altname:
            result["altname"] = self.altname
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        if self.is_function:
            vty = cast("BCTypFun", self.vtype)
            return (
                str(vty.returntype)
                + " "
                + self.vname
                + str(vty.argtypes))
        else:
            if self.vtype:
                return str(self.vtype) + " " + self.displayname
            else:
                return self.displayname

    def __str__(self) -> str:
        if self.altname:
            return self.altname
        else:
            return self.vname


class ASTFormalVarInfo(ASTVarInfo):
    """Represents a formal parameter of a function in C source view.

    The parameter index refers to the source view index (zero-based).
    The arglocs field holds the locations where the argument to the
    function are stored upon function entry. In most cases this will
    be a single location (register or stack). C, however, allows struct
    arguments, which may be distributed over multiple argument locations.
    To adequately represent this case, offsets are added that represent
    which field is in which argument location. If the struct includes
    arrays (possibly packed arrays of e.g., chars), the starting index
    of these arrays is represented as well.

    The argindex refers to the actual argument index in the binary
    (zero-based).

    The arglocs (argument locations) is a list of tuples consisting of:
    - the location (represented as a string, e.g., 'R0', or 'stack:16')
    - the offset, if this argument is a field in a struct (default NoOffset)
    - the starting index, if this is an array broken up into multiple parts
      (default 0)
    """

    def __init__(
            self,
            id: int,
            vname: str,
            vtype: Optional["BCTyp"],
            parameter: int,
            argindex: int) -> None:
        ASTVarInfo.__init__(
            self, id, vname, vtype, None, parameter, None, None)
        self._argindex = argindex
        self._arglocs: List[Tuple[str, "ASTOffset", int]] = []

    @property
    def arglocs(self) -> List[Tuple[str, "ASTOffset", int]]:
        return self._arglocs

    def argloc(self, index: int) -> Tuple[str, "ASTOffset", int]:
        if len(self.arglocs) > index:
            return self.arglocs[index]
        else:
            raise Exception(
                "Formal "
                + self.vname
                + ": illegal index: "
                + str(index)
                + " (number of argument locations: "
                + str(len(self.arglocs)))

    @property
    def numargs(self) -> int:
        return len(self.arglocs)

    @property
    def argindex(self) -> int:
        return self._argindex

    def initialize(self, new_id: Callable[[], int], callingconvention: str) -> int:
        argtype = self.vtype
        if argtype is not None:
            if callingconvention == "arm":
                return self._initialize_arm_arguments(new_id, argtype)
            elif callingconvention == "mips":
                return self._initialize_mips_arguments(new_id, argtype)
            else:
                raise Exception(
                    "Calling convention " + str(callingconvention) + " not recognized")
        else:
            raise Exception(
                "Formal parameter has no type")

    def _initialize_arm_arguments(
            self, new_id: Callable[[], int], argtype: "BCTyp") -> int:
        """Set up arguments according to the standard ARM ABI.

        The default calling convention for ARM:
        - the first four arguments are passed in R0, R1, R2, R3
        - subsequent arguments are passed on the stack starting at offset 0
        """
        if argtype.is_scalar:
            argloc = get_arg_loc("arm", self.argindex)
            self._arglocs.append((argloc, ASTNoOffset(-1), 0))
            return self.argindex + 1
        elif argtype.is_struct:
            structtyp = cast("BCTypComp", argtype)
            fieldoffsets = structtyp.compinfo.fieldoffsets()
            fieldcounter = 0
            for (offset, finfo) in fieldoffsets:
                if finfo.fieldname.startswith("__"):
                    continue    # padding field for alignment
                if finfo.byte_size() <= 4:
                    argloc = get_arg_loc("arm", self.argindex + fieldcounter)
                    fieldcounter += 1
                    fieldoffset = ASTFieldOffset(
                        new_id(),
                        finfo.fieldname,
                        finfo.fieldtype,
                        ASTNoOffset(-1))
                    self._arglocs.append((argloc, fieldoffset, 0))
                else:
                    if finfo.fieldtype.is_array:
                        atype = cast("BCTypArray", finfo.fieldtype)
                        if (
                                atype.has_constant_size()
                                and atype.tgttyp.byte_size() == 1):
                            # assume array elements are packed
                            argcount = atype.byte_size() // 4
                            for i in range(0, argcount):
                                argloc = get_arg_loc(
                                    "arm", self.argindex + fieldcounter)
                                fieldcounter += 1
                                fieldoffset = ASTFieldOffset(
                                    new_id(),
                                    finfo.fieldname,
                                    finfo.fieldtype,
                                    ASTNoOffset(-1))
                                self._arglocs.append((argloc, fieldoffset, i * 4))
            for loc in self._arglocs:
                print(str(loc[0]) + ", " + str(loc[1]))
            return self.argindex + fieldcounter
        else:
            return 0

    def _initialize_mips_arguments(
            self, new_id: Callable[[], int], argtype: "BCTyp") -> int:
        if argtype.is_scalar or argtype.is_pointer:
            argloc = get_arg_loc("mips", self.argindex)
            self._arglocs.append((argloc, ASTNoOffset(-1), 0))
            return self.argindex + 1
        else:
            print("Argument type is not a scalar: " + str(argtype))
            return 0

    def __str__(self) -> str:
        if len(self.arglocs) == 1:
            p_arglocs = self.arglocs[0][0]
        else:
            p_arglocs = ", ".join(
                str(loc) + ": " + str(offset) for (loc, offset, _) in self.arglocs)
        return ASTVarInfo.__str__(self) + " (" + p_arglocs + ")"


class ASTVariable(ASTLHost):

    def __init__(
            self,
            id: int,
            varinfo: ASTVarInfo) -> None:
        ASTLHost.__init__(self, id, "var")
        self._varinfo = varinfo

    @property
    def is_ignored(self) -> bool:
        return self.varinfo.is_ignored

    @property
    def varinfo(self) -> ASTVarInfo:
        return self._varinfo

    @property
    def vname(self) -> str:
        return self.varinfo.vname

    @property
    def ctype(self) -> Optional["BCTyp"]:
        return self.varinfo.vtype

    @property
    def is_global(self) -> bool:
        return self.varinfo.is_global

    @property
    def displayname(self) -> str:
        if self.varinfo.altname:
            return self.varinfo.altname
        else:
            return self.vname

    @property
    def is_variable(self) -> bool:
        return True

    def has_altname(self) -> bool:
        return self.varinfo.has_altname()

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
            result: List[ASTNodeRecord] = []
            result.append(self.noderecord())
            # result.extend(self.varinfo.serialize())
            return result

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

    @property
    def ctype(self) -> Optional["BCTyp"]:
        exptype = self.memexp.ctype
        if exptype is not None:
            return exptype.bcd.ptr_to(exptype)
        else:
            return None

    @property
    def is_memref(self) -> bool:
        return True

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

    def transform_subx(self, usedefs_e: UseDef) -> "ASTMemRef":
        xmemexp = self.memexp.transform_subx(usedefs_e)
        return ASTMemRef(self.id, xmemexp)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTMemRef":
        r_memexp = self.memexp.reduce(mapping, live_x, macronames)
        return ASTMemRef(self.id, r_memexp)

    def to_c_like(self, sp: int = 0) -> str:
        return "(*(" + self.memexp.to_c_like() + "))"

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        lines.append(self.memexp.to_string(sp + 2))
        return "\n".join(lines)

    def __str__(self) -> str:
        return str(self.memexp)


class ASTOffset(ASTNode):

    def __init__(self, id: int, tag: str) -> None:
        ASTNode.__init__(self, id, tag)

    @property
    def is_ast_offset(self) -> bool:
        return True

    @property
    def is_field_offset(self) -> bool:
        return False

    @property
    def is_index_offset(self) -> bool:
        return False

    @property
    def is_no_offset(self) -> bool:
        return False

    def offset_ctype(self, basetype: Optional["BCTyp"]) -> Optional["BCTyp"]:
        return None

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])

    def transform_subx(self, usedefs_e: UseDef) -> "ASTOffset":
        return self

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTOffset":
        return self


class ASTNoOffset(ASTOffset):

    def __init__(self, id: int) -> None:
        ASTOffset.__init__(self, id, "no-offset")

    @property
    def is_no_offset(self) -> bool:
        return True

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])

    def to_c_like(self, sp: int = 0) -> str:
        return ""

    def __str__(self) -> str:
        return ""


class ASTFieldOffset(ASTOffset):

    def __init__(
            self,
            id: int,
            fieldname: str,
            fieldtype: "BCTyp",
            offset: "ASTOffset") -> None:
        ASTOffset.__init__(self, id, "field-offset")
        self._fieldname = fieldname
        self._fieldtype = fieldtype
        self._offset = offset

    @property
    def fieldname(self) -> str:
        return self._fieldname

    @property
    def fieldtype(self) -> "BCTyp":
        return self._fieldtype

    @property
    def offset(self) -> "ASTOffset":
        return self._offset

    @property
    def is_field_offset(self) -> bool:
        return True

    def offset_ctype(self, basetype: Optional["BCTyp"]) -> Optional["BCTyp"]:
        if self.offset.is_no_offset:
            return self.fieldtype
        else:
            return self.offset.offset_ctype(self.fieldtype)

    def address_taken(self) -> Set[str]:
        return self.offset.address_taken()

    def variables_used(self) -> Set[str]:
        return self.offset.variables_used()

    def use(self) -> List[str]:
        return self.offset.use()

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTFieldOffset":
        r_offset = self.offset.reduce(mapping, live_x, macronames)
        return ASTFieldOffset(self.id, self.fieldname, self.fieldtype, r_offset)

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [self.offset.id]
        result["fname"] = self.fieldname
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        if self.offset.id != -1:
            result.extend(self.offset.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        return "." + self.fieldname + self.offset.to_c_like()

    def __str__(self) -> str:
        return "." + self.fieldname + str(self.offset)


class ASTIndexOffset(ASTOffset):

    def __init__(self, id, index: "ASTExpr", offset: "ASTOffset") -> None:
        ASTOffset.__init__(self, id, "index-offset")
        self._index = index
        self._offset = offset

    @property
    def index(self) -> "ASTExpr":
        return self._index

    @property
    def offset(self) -> "ASTOffset":
        return self._offset

    @property
    def is_index_offset(self) -> bool:
        return True

    def offset_ctype(self, basetype: Optional["BCTyp"]) -> Optional["BCTyp"]:
        if basetype is None:
            return None
        elif basetype.is_array:
            bt = cast("BCTypArray", basetype)
            if self.offset.is_no_offset:
                return bt.tgttyp
            else:
                return self.offset.offset_ctype(bt.tgttyp)
        else:
            return None

    def address_taken(self) -> Set[str]:
        return self.index.address_taken().union(self.offset.address_taken())

    def variables_used(self) -> Set[str]:
        return self.index.variables_used().union(self.offset.variables_used())

    def use(self) -> List[str]:
        return self.index.use() + self.offset.use()

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTIndexOffset":
        r_index = self.index.reduce(mapping, live_x, macronames)
        r_offset = self.offset.reduce(mapping, live_x, macronames)
        return ASTIndexOffset(self.id, r_index, r_offset)

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [self.index.id, self.offset.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.index.serialize())
        if self.offset.id != -1:
            result.extend(self.offset.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        return "[" + self.index.to_c_like() + "]" + self.offset.to_c_like()

    def __str__(self) -> str:
        return "[" + str(self.index) + "]" + str(self.offset)


class ASTExpr(ASTNode):

    def __init__(self, id: int, tag: str) -> None:
        ASTNode.__init__(self, id, tag)

    @property
    def is_ast_expr(self) -> bool:
        return True

    @property
    def is_ast_constant(self) -> bool:
        return False

    @property
    def is_ast_lval_expr(self) -> bool:
        return False

    @property
    def is_ast_substituted_expr(self) -> bool:
        return False

    @property
    def is_ast_cast_expr(self) -> bool:
        return False

    @property
    def is_ast_unary_op(self) -> bool:
        return False

    @property
    def is_ast_binary_op(self) -> bool:
        return False

    @property
    def is_ast_question(self) -> bool:
        return False

    @property
    def is_ast_addressof(self) -> bool:
        return False

    @property
    def is_integer_constant(self) -> bool:
        return False

    @property
    def cvalue(self) -> int:
        raise Exception("Internal error in ASTExpr: " + str(self))

    @property
    def ctype(self) -> Optional["BCTyp"]:
        return None

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])

    def transform_subx(self, usedefs: UseDef) -> "ASTExpr":
        return self

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTExpr":
        return self


class ASTConstant(ASTExpr):

    def __init__(self, id: int, tag: str) -> None:
        ASTExpr.__init__(self, id, tag)

    @property
    def is_ast_constant(self) -> bool:
        return True

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])


class ASTIntegerConstant(ASTConstant):

    def __init__(self, id: int, cvalue: int, macroname: Optional[str] = None) -> None:
        ASTConstant.__init__(self, id, "integer-constant")
        self._cvalue = cvalue
        self._macroname = macroname

    @property
    def cvalue(self) -> int:
        return self._cvalue

    @property
    def macroname(self) -> Optional[str]:
        return self._macroname

    @property
    def is_integer_constant(self) -> bool:
        return True

    def use(self) -> List[str]:
        return []

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTExpr":
        if self.cvalue in macronames:
            macroname = macronames[self.cvalue]
            return ASTIntegerConstant(self.id, self.cvalue, macroname)
        else:
            return self

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["value"] = str(self.cvalue)
        if self.macroname:
            result["macroname"] = self.macroname
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        return [self.noderecord()]

    def to_c_like(self, sp: int = 0) -> str:
        if self.macroname:
            return self.macroname
        elif self.cvalue > 100000:
            return hex(self.cvalue)
        else:
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
    def is_ast_lval_expr(self) -> bool:
        return True

    @property
    def lval(self) -> "ASTLval":
        return self._lval

    @property
    def ctype(self) -> Optional["BCTyp"]:
        return self.lval.ctype

    def address_taken(self) -> Set[str]:
        return self.lval.address_taken()

    def variables_used(self) -> Set[str]:
        return self.lval.variables_used()

    def use(self) -> List[str]:
        return self.lval.use()

    def transform_subx(self, usedefs_e: UseDef) -> "ASTExpr":
        name = str(self.lval)
        if usedefs_e.has_name(name):
            (assign_id, expr) = usedefs_e.get(name)
            if name in expr.use():
                # Don't replace variable if it occurs in expression
                return self
            elif self.lval.has_altname():
                # Don't replace names given by the user
                return self
            else:
                return ASTSubstitutedExpr(self.id, self.lval, assign_id, expr)
        else:
            xlval = self.lval.transform_subx(usedefs_e)
            return ASTLvalExpr(self.id, xlval)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTExpr":
        r_lval = self.lval.reduce(mapping, live_x, macronames)
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
        ASTLvalExpr.__init__(self, id, lval, tag="substituted-expr")
        self._assign_id = assign_id
        self._expr = expr

    @property
    def is_ast_substituted_expr(self) -> bool:
        return True

    @property
    def assign_id(self) -> int:
        return self._assign_id

    @property
    def substituted_expr(self) -> "ASTExpr":
        return self._expr

    @property
    def is_integer_constant(self) -> bool:
        return self.substituted_expr.is_integer_constant

    @property
    def cvalue(self) -> int:
        if self.is_integer_constant:
            return self.substituted_expr.cvalue
        else:
            raise Exception("Internal error in substituted expression")

    def use(self) -> List[str]:
        return self.substituted_expr.use()

    def transform_subx(self, usedefs_e: UseDef) -> "ASTExpr":
        xform_exp = self.substituted_expr.transform_subx(usedefs_e)
        if str(self.lval) in xform_exp.use():
            return self
        else:
            return ASTSubstitutedExpr(self.id, self.lval, self.assign_id, xform_exp)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTExpr":
        if self.is_integer_constant:
            return ASTIntegerConstant(
                self.id, self.cvalue).reduce(mapping, live_x, macronames)
        else:
            # mapping[self.id] = self.substituted_expr.id
            r_lval = self.lval.reduce(mapping, live_x, macronames)
            r_substituted_expr = self.substituted_expr.reduce(mapping, live_x, macronames)
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
        result.extend(self.substituted_expr.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        return self.substituted_expr.to_c_like()

    def __str__(self) -> str:
        return str(self.substituted_expr)


class ASTCastE(ASTExpr):

    def __init__(self, id: int, tgttyp: str, exp: "ASTExpr") -> None:
        ASTExpr.__init__(self, id, "cast-expr")
        self._tgttyp = tgttyp
        self._exp = exp

    @property
    def is_ast_cast_expr(self) -> bool:
        return True

    @property
    def tgttyp(self) -> str:
        return self._tgttyp

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
        result["args"] = [self.exp.id]
        result["type"] = self.tgttyp
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.exp.serialize())
        return result

    def transform_subx(self, usedefs_e: UseDef) -> "ASTCastE":
        xform_exp = self.exp.transform_subx(usedefs_e)
        return ASTCastE(self.id, self.tgttyp, xform_exp)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTCastE":
        return ASTCastE(
            self.id, self.tgttyp, self.exp.reduce(mapping, live_x, macronames))

    def to_c_like(self, sp: int = 0) -> str:
        return "(" + str(self.tgttyp) + ")" + self.exp.to_c_like()

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        lines.append(self.exp.to_string(sp + 2))
        return "\n".join(lines)

    def __str__(self) -> str:
        return "((" + str(self.tgttyp) + ")" + str(self.exp) + ")"


class ASTUnaryOp(ASTExpr):

    def __init__(self, id: int, op: str,  exp: "ASTExpr") -> None:
        ASTExpr.__init__(self, id, "unary-op")
        self._op = op
        self._exp = exp

    @property
    def is_ast_unary_op(self) -> bool:
        return True

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
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTUnaryOp":
        return ASTUnaryOp(
            self.id, self.op, self.exp.reduce(mapping, live_x, macronames))

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
    def is_ast_binary_op(self) -> bool:
        return True

    @property
    def op(self) -> str:
        return self._op

    @property
    def exp1(self) -> "ASTExpr":
        return self._exp1

    @property
    def exp2(self) -> "ASTExpr":
        return self._exp2

    @property
    def is_integer_constant(self) -> bool:
        return (
            self.exp1.is_integer_constant
            and self.exp2.is_integer_constant
            and self.op in ["plus", "minus"])

    @property
    def cvalue(self) -> int:
        if self.op in ["plus", "minus"]:
            if self.exp1.is_integer_constant and self.exp2.is_integer_constant:
                return self.exp1.cvalue + self.exp2.cvalue
            else:
                raise Exception("Internal error in binary op: " + str(self))
        else:
            raise Exception("Internal error in binary op: " + str(self))

    def address_taken(self) -> Set[str]:
        return self.exp1.address_taken().union(self.exp2.address_taken())

    def variables_used(self) -> Set[str]:
        return self.exp1.variables_used().union(self.exp2.variables_used())

    def use(self) -> List[str]:
        return self.exp1.use() + self.exp2.use()

    def transform_subx(self, usedefs_e: UseDef) -> "ASTBinaryOp":
        xform_exp1 = self.exp1.transform_subx(usedefs_e)
        xform_exp2 = self.exp2.transform_subx(usedefs_e)
        return ASTBinaryOp(self.id, self.op, xform_exp1, xform_exp2)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTExpr":
        r_exp1 = self.exp1.reduce(mapping, live_x, macronames)
        r_exp2 = self.exp2.reduce(mapping, live_x, macronames)
        if (
                r_exp1.is_integer_constant
                and r_exp2.is_integer_constant
                and self.op in ["plus", "minus"]):
            if self.op == "plus":
                result = r_exp1.cvalue + r_exp2.cvalue
                return ASTIntegerConstant(
                    self.id, result).reduce(mapping, live_x, macronames)
            else:
                return ASTBinaryOp(self.id, self.op, r_exp1, r_exp2)
        else:
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
        return (
            "("
            + self.exp1.to_c_like()
            + operators[self.op]
            + self.exp2.to_c_like()
            + ")")

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp) + ":" + self.op)
        lines.append(self.exp1.to_string(sp + 2))
        lines.append(self.exp2.to_string(sp + 2))
        return "\n".join(lines)

    def __str__(self) -> str:
        return "(" + str(self.exp1) + operators[self.op] + str(self.exp2) + ")"


class ASTQuestion(ASTExpr):

    def __init__(
            self,
            id: int,
            exp1: "ASTExpr",
            exp2: "ASTExpr",
            exp3: "ASTExpr") -> None:
        ASTExpr.__init__(self, id, "question")
        self._exp1 = exp1
        self._exp2 = exp2
        self._exp3 = exp3

    @property
    def is_ast_question(self) -> bool:
        return True

    @property
    def exp1(self) -> "ASTExpr":
        return self._exp1

    @property
    def exp2(self) -> "ASTExpr":
        return self._exp2

    @property
    def exp3(self) -> "ASTExpr":
        return self._exp3

    def address_taken(self) -> Set[str]:
        return self.exp1.address_taken().union(self.exp2.address_taken()).union(self.exp3.address_taken())

    def variables_used(self) -> Set[str]:
        return self.exp1.variables_used().union(self.exp2.variables_used()).union(self.exp3.variables_used())

    def transform_subx(self, usedefs_e: UseDef) -> "ASTQuestion":
        xform_exp1 = self.exp1.transform_subx(usedefs_e)
        xform_exp2 = self.exp2.transform_subx(usedefs_e)
        xform_exp3 = self.exp3.transform_subx(usedefs_e)
        return ASTQuestion(self.id, xform_exp1, xform_exp2, xform_exp3)

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTExpr":
        r_exp1 = self.exp1.reduce(mapping, live_x, macronames)
        r_exp2 = self.exp2.reduce(mapping, live_x, macronames)
        r_exp3 = self.exp3.reduce(mapping, live_x, macronames)
        return ASTQuestion(self.id, r_exp1, r_exp2, r_exp3)

    def noderecord(self) -> ASTNodeRecord:
        result = ASTNode.noderecord(self)
        result["args"] = [self.exp1.id, self.exp2.id, self.exp3.id]
        return result

    def serialize(self) -> List[ASTNodeRecord]:
        result: List[ASTNodeRecord] = []
        result.append(self.noderecord())
        result.extend(self.exp1.serialize())
        result.extend(self.exp2.serialize())
        result.extend(self.exp3.serialize())
        return result

    def to_c_like(self, sp: int = 0) -> str:
        return (
            "("
            + self.exp1.to_c_like()
            + " ? "
            + self.exp2.to_c_like()
            + " : "
            + self.exp3.to_c_like()
            + ")")

    def __str_(self) -> str:
        return (
            "("
            + str(self.exp1)
            + " ? "
            + str(self.exp2)
            + " : "
            + str(self.exp3)
            + ")")


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
        return [str(self.lval)]

    def reduce(
            self,
            mapping: Dict[int, int],
            live_x: Mapping[int, Set[str]] = {},
            macronames: Mapping[int, str] = {}) -> "ASTAddressOf":
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
