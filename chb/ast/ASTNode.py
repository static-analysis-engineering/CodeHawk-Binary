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

from chb.ast.ASTUtil import InstrUseDef, UseDef, get_arg_loc
from chb.ast.ASTVarInfo import ASTVarInfo

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.bctypes.BCTyp import (
        BCTyp, BCTypPtr, BCTypFun, BCTypArray, BCTypComp)
    from chb.ast.ASTTransformer import ASTTransformer
    from chb.ast.ASTVarInfo import ASTVarInfo
    from chb.ast.ASTVisitor import ASTVisitor


c_indent = 3

"""
Names used in relation to CIL sum types:

Unary operators:
 Neg: "neg"
 BNot: "bnot"
 LNot: "lnot"

Binary operators:    
 PlusA: "plusa"
 PlusPI: "pluspi"
 IndexPI: "indexpi"
 MinusA: "minusa"
 MinusPI: "minuspi"
 MinusPP: "minuspp"
 Mult: "mult"
 Div: "div"
 Mod: "mod"
 Shiftlt: "shiftlt"
 Shiftrt: "shiftrt"
 Lt: "lt"
 Gt: "gt"
 Le: "le"
 Ge: "ge"
 Eq: "eq"
 Ne: "ne"
 BAnd: "band"
 BXor: "bxor"
 BOr: "bor"
 LAnd: "land"
 LOr: "lor"

"""

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
    "minus": " - ",
    "mod": " % ",     
    "mult": " * ",   # multiplication
    "ne": " != ",
    "neq": " != ",
    "plus": " + ",
    "shiftlt": " << ",
    "shiftrt": " >> "
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

    def __init__(self, tag: str) -> None:
        self._tag = tag

    @property
    def tag(self) -> str:
        return self._tag

    @abstractmethod
    def accept(self, visitor: "ASTVisitor") -> None:
        ...

    @abstractmethod
    def transform(self, transformer: "ASTTransformer") -> "ASTNode":
        ...

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

    def variables_used(self) -> Set[str]:
        return set([])

    def callees(self) -> Set[str]:
        return set([])

    def to_c_like(self, sp: int = 0) -> str:
        return (" " * sp) + self.tag

    def to_string(self, sp: int = 0) -> str:
        return (" " * sp) + self.tag

    def structure_to_string(self, sp: int = 0) -> str:
        return (" " * sp) + self.tag

    def __str__(self) -> str:
        return self.tag


class ASTStmt(ASTNode):

    def __init__(self, stmtid: int, tag: str) -> None:
        ASTNode.__init__(self, tag)
        self._stmtid = stmtid

    @property
    def stmtid(self) -> int:
        return self._stmtid

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

    @abstractmethod
    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        ...

    def is_empty(self) -> bool:
        return False

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])

    def callees(self) -> Set[str]:
        return set([])

    def structure_to_string(self, sp: int = 0) -> str:
        return (" " * sp) + self.tag


class ASTReturn(ASTStmt):

    def __init__(self, stmtid: int, expr: Optional["ASTExpr"]) -> None:
        ASTStmt.__init__(self, stmtid, "return")
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

    def accept(self, visitor: "ASTVisitor") -> None:
        return visitor.visit_return_stmt(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        return transformer.transform_return_stmt(self)

    def has_return_value(self) -> bool:
        return self._expr is not None

    def address_taken(self) -> Set[str]:
        if self.has_return_value():
            return self.expr.address_taken()
        else:
            return set([])

    def variables_used(self) -> Set[str]:
        if self.has_return_value():
            return self.expr.variables_used()
        else:
            return set([])

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

    def __init__(self, stmtid: int, stmts: List["ASTStmt"]) -> None:
        ASTStmt.__init__(self, stmtid, "block")
        self._stmts = stmts

    @property
    def is_ast_block(self) -> bool:
        return True

    @property
    def stmts(self) -> Sequence["ASTStmt"]:
        return self._stmts

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_block_stmt(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        return transformer.transform_block_stmt(self)

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

    def __init__(self, stmtid: int, instrs: List["ASTInstruction"]) -> None:
        ASTStmt.__init__(self, stmtid, "instrs")
        self._instrs: List["ASTInstruction"] = instrs
        self._aexp: Dict[int, List["ASTExpr"]] = {}

    @property
    def is_ast_instruction_sequence(self) -> bool:
        return True

    @property
    def instructions(self) -> Sequence["ASTInstruction"]:
        return self._instrs

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_instruction_sequence_stmt(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        return transformer.transform_instruction_sequence_stmt(self)

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
            stmtid: int,
            cond: "ASTExpr",
            ifstmt: "ASTStmt",
            elsestmt: "ASTStmt",
            relative_offset: int) -> None:
        ASTStmt.__init__(self, stmtid, "if")
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

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_branch_stmt(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        return transformer.transform_branch_stmt(self)

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
        lines.append("Condition: " + str(self.condition))
        lines.append("  Then   : " + str(self.ifstmt.stmtid))
        lines.append("  Else   : " + str(self.elsestmt.stmtid))
        return "\n".join(lines)


class ASTInstruction(ASTNode, ABC):

    def __init__(self, instrid: int, tag: str) -> None:
        ASTNode.__init__(self, tag)
        self._instrid = instrid

    @property
    def instrid(self) -> int:
        return self._instrid

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
    def define(self) -> "ASTLval":
        ...

    @abstractmethod
    def transform(self, transformer: "ASTTransformer") -> "ASTInstruction":
        ...

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])

    def callees(self) -> Set[str]:
        return set([])

    def use(self) -> List[str]:
        return []


class ASTAssign(ASTInstruction):

    def __init__(
            self,
            instrid: int,
            lhs: "ASTLval",
            rhs: "ASTExpr",
            annotations: List[str] = []) -> None:
        ASTInstruction.__init__(self, instrid, "assign")
        self._lhs = lhs
        self._rhs = rhs
        self._annotations = annotations

    @property
    def is_ast_assign(self) -> bool:
        return True

    @property
    def lhs(self) -> "ASTLval":
        return self._lhs

    @property
    def rhs(self) -> "ASTExpr":
        return self._rhs

    @property
    def annotations(self) -> List[str]:
        return self._annotations

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_assign_instr(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTInstruction":
        return transformer.transform_assign_instr(self)

    def address_taken(self) -> Set[str]:
        return self.lhs.address_taken().union(self.rhs.address_taken())

    def variables_used(self) -> Set[str]:
        return self.lhs.variables_used().union(self.rhs.variables_used())

    def callees(self) -> Set[str]:
        return set([])

    def define(self) -> "ASTLval":
        return self.lhs

    def use(self) -> List[str]:
        return self.rhs.use()

    def kill(self) -> List["ASTLval"]:
        return [self.define()]

    def to_c_like(self, sp: int = 0) -> str:
        annotations = str(self.instrid)
        if len(self.annotations) > 0:
            annotations = " " + ", ".join(self.annotations)
        default = (
            (" " * sp)
            + self.lhs.to_c_like()
            + " = "
            + self.rhs.to_c_like()
            + ";"
            + " // "
            + annotations)
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
            instrid: int,
            lhs: "ASTLval",
            tgt: "ASTExpr",
            args: List["ASTExpr"]) -> None:
        ASTInstruction.__init__(self, instrid, "call")
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

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_call_instr(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTInstruction":
        return transformer.transform_call_instr(self)

    def address_taken(self) -> Set[str]:
        return self.tgt.address_taken().union(
            *(a.address_taken() for a in self.arguments))

    def variables_used(self) -> Set[str]:
        return self.lhs.variables_used().union(
            self.tgt.variables_used()).union(
                *(a.variables_used() for a in self.arguments))

    def callees(self) -> Set[str]:
        return set([str(self.tgt)])

    def define(self) -> "ASTLval":
        return self.lhs

    def use(self) -> List[str]:
        result = []
        result.extend(self.tgt.use())
        for a in self.arguments:
            result.extend(a.use())
        return result

    def kill(self) -> List[str]:
        return ["R0", "R1", "R2", "R3", "$v0", "$v1", str(self.lhs)]

    def to_c_like(self, sp: int = 0) -> str:
        indent = " " * sp
        calltgt = (
            self.tgt.to_c_like()
            + "("
            + ", ".join(str(a.to_c_like()) for a in self.arguments)
            + ");  // " + str(self.instrid))
        return indent + self.lhs.to_c_like() + " = " + calltgt

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        lines.append(self.lhs.to_string(sp + 2))
        lines.append(self.tgt.to_string(sp + 2))
        for a in self.arguments:
            lines.append(a.to_string(sp + 2))
        return "\n".join(lines)

    def __str__(self) -> str:
        lines: List[str] = []
        lhs = str(self.lhs)
        lines.append(ASTNode.__str__(self))
        lines.append(lhs)
        lines.append("  " + str(self.tgt))
        lines.append("  " + "\n  ".join(str(a) for a in self.arguments))
        return "\n".join(lines)


class ASTLval(ASTNode):

    def __init__(self, lhost: "ASTLHost", offset: "ASTOffset") -> None:
        ASTNode.__init__(self, "lval")
        self._lhost = lhost
        self._offset = offset

    @property
    def is_ast_lval(self) -> bool:
        return True

    @property
    def lhost(self) -> "ASTLHost":
        return self._lhost

    @property
    def offset(self) -> "ASTOffset":
        return self._offset

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_lval(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTLval":
        return transformer.transform_lval(self)

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
    def is_variable(self) -> bool:
        return self.lhost.is_variable

    @property
    def is_global(self) -> bool:
        return self.lhost.is_global

    def address_taken(self) -> Set[str]:
        return self.lhost.address_taken().union(self.offset.address_taken())

    def variables_used(self) -> Set[str]:
        return self.lhost.variables_used().union(self.offset.variables_used())

    def offset_to_string(self, sp: int = 0) -> str:
        if self.offset.is_no_offset:
            return ""
        else:
            return self.offset.to_string(sp)

    def use(self) -> List[str]:
        return self.lhost.use() + self.offset.use()

    def to_c_like(self, sp: int = 0) -> str:
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
        if not self.offset.is_no_offset:
            lines.append(self.offset_to_string(sp + 2))
        return "\n".join(lines)

    def __str__(self) -> str:
        return str(self.lhost) + str(self.offset)


class ASTLHost(ASTNode):

    def __init__(self, tag: str) -> None:
        ASTNode.__init__(self, tag)

    @property
    def is_ast_lhost(self) -> bool:
        return True

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

    @abstractmethod
    def transform(self, transformer: "ASTTransformer") -> "ASTLHost":
        ...

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])


class ASTVariable(ASTLHost):

    def __init__(self, varinfo: ASTVarInfo) -> None:
        ASTLHost.__init__(self, "var")
        self._varinfo = varinfo

    @property
    def is_variable(self) -> bool:
        return True
        
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

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_variable(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTLHost":
        return transformer.transform_variable(self)

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([self.vname])

    def use(self) -> List[str]:
        if self.vname == "PC":
            return []
        else:
            return [self.vname]

    def to_c_like(self, sp: int = 0) -> str:
        return self.vname

    def to_string(self, sp: int = 0) -> str:
        return ASTNode.to_string(self, sp) + "(" + self.vname + ")"

    def __str__(self):
        return self.vname


class ASTMemRef(ASTLHost):

    def __init__(
            self,
            memexp: "ASTExpr") -> None:
        ASTLHost.__init__(self, "memref")
        self._memexp = memexp

    @property
    def is_memref(self) -> bool:
        return True
        
    @property
    def memexp(self) -> "ASTExpr":
        return self._memexp

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_memref(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTLHost":
        return transformer.transform_memref(self)        

    @property
    def ctype(self) -> Optional["BCTyp"]:
        exptype = self.memexp.ctype
        if exptype is not None:
            return exptype.bcd.ptr_to(exptype)
        else:
            return None

    def address_taken(self) -> Set[str]:
        return self.memexp.address_taken()

    def variables_used(self) -> Set[str]:
        return self.memexp.variables_used()

    def use(self) -> List[str]:
        return self.memexp.use()

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

    def __init__(self, tag: str) -> None:
        ASTNode.__init__(self, tag)

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

    @abstractmethod
    def transform(self, transformer: "ASTTransformer") -> "ASTOffset":
        ...

    def offset_ctype(self, basetype: Optional["BCTyp"]) -> Optional["BCTyp"]:
        return None

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])


class ASTNoOffset(ASTOffset):

    def __init__(self) -> None:
        ASTOffset.__init__(self, "no-offset")

    @property
    def is_no_offset(self) -> bool:
        return True

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_no_offset(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTOffset":
        return transformer.transform_no_offset(self)

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
            fieldname: str,
            fieldtype: "BCTyp",
            offset: "ASTOffset") -> None:
        ASTOffset.__init__(self, "field-offset")
        self._fieldname = fieldname
        self._fieldtype = fieldtype
        self._offset = offset

    @property
    def is_field_offset(self) -> bool:
        return True
        
    @property
    def fieldname(self) -> str:
        return self._fieldname

    @property
    def fieldtype(self) -> "BCTyp":
        return self._fieldtype

    @property
    def offset(self) -> "ASTOffset":
        return self._offset

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_field_offset(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTOffset":
        return transformer.transform_field_offset(self)

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

    def to_c_like(self, sp: int = 0) -> str:
        return "." + self.fieldname + self.offset.to_c_like()

    def __str__(self) -> str:
        return "." + self.fieldname + str(self.offset)


class ASTIndexOffset(ASTOffset):

    def __init__(self, index: "ASTExpr", offset: "ASTOffset") -> None:
        ASTOffset.__init__(self, "index-offset")
        self._index = index
        self._offset = offset

    @property
    def is_index_offset(self) -> bool:
        return True
        
    @property
    def index(self) -> "ASTExpr":
        return self._index

    @property
    def offset(self) -> "ASTOffset":
        return self._offset

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_index_offset(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTOffset":
        return transformer.transform_index_offset(self)

    def offset_ctype(self, basetype: Optional["BCTyp"]) -> Optional["BCTyp"]:
        if basetype is None:
            return None
        elif basetype.is_array:
            btarray = cast("BCTypArray", basetype)
            if self.offset.is_no_offset:
                return btarray.tgttyp
            else:
                return self.offset.offset_ctype(btarray.tgttyp)
        elif basetype.is_pointer:
            btptr = cast("BCTypPtr", basetype)
            if self.offset.is_no_offset:
                return btptr.tgttyp
            else:
                return self.offset.offset_ctype(btptr.tgttyp)
        else:
            return None

    def address_taken(self) -> Set[str]:
        return self.index.address_taken().union(self.offset.address_taken())

    def variables_used(self) -> Set[str]:
        return self.index.variables_used().union(self.offset.variables_used())

    def use(self) -> List[str]:
        return self.index.use() + self.offset.use()

    def to_c_like(self, sp: int = 0) -> str:
        return "[" + self.index.to_c_like() + "]" + self.offset.to_c_like()

    def __str__(self) -> str:
        return "[" + str(self.index) + "]" + str(self.offset)


class ASTExpr(ASTNode):
    """Universal interface to all expression types.

    This class presents the union of properties and methods for all subclasses,
    but calls will fail (or return None in case of an optional returntype) on 
    those properties and methods not supported for the subclass they are called
    on.

    This approach requires checking the subclass with the is_... property, but
    avoids the need for subsequent explicit casting (for type checking).
    """

    def __init__(self, tag: str) -> None:
        ASTNode.__init__(self, tag)

    @property
    def is_ast_expr(self) -> bool:
        return True

    @property
    def is_ast_constant(self) -> bool:
        return False

    @property
    def is_integer_constant(self) -> bool:
        return False

    @property
    def is_global_address(self) -> bool:
        return False
   
    @property
    def is_string_constant(self) -> bool:
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
    def cvalue(self) -> int:
        """Applicable only if is_integer_constant."""

        raise UF.CHBError(
            "Property cvalue not supported on expr type: " + self.tag)

    @property
    def ctype(self) -> Optional["BCTyp"]:        
        return None

    @property
    def address_expr(self) -> "ASTExpr":
        """Applicable only if is_global_address or is_string_address."""

        raise UF.CHBError(
            "Property address_expr not supported on expr type: " + self.tag)
        

    @property
    def address_tgt_type(self) -> Optional["BCTyp"]:
        """Applicable only if is_global_address or is_ast_addressof."""

        raise UF.CHBError(
            "Property address_tgt_type not supported on expr type: " + self.tag)

    @property
    def cstr(self) -> str:
        """Applicable only if is_string_address."""

        raise UF.CHBError(
            "Property cstr not supported on expr type: " + self.tag)

    @property
    def string_address(self) -> str:
        """Applicable only if is_string_address."""

        raise UF.CHBError(
            "Property string_address not supported on expr type: " + self.tag)

    @property
    def lval(self) -> "ASTLval":
        """Applicable only if is_ast_lval_expr or is_ast_addressof."""

        raise UF.CHBError(
            "Property lval not supported on expr type: " + self.tag)

    @property
    def assign_id(self) -> int:
        """Applicable only if is_ast_substituted_expr."""

        raise UF.CHBError(
            "Property assign_id not supported on expr type: " + self.tag)

    @property
    def substituted_expr(self) -> "ASTExpr":
        """Applicable only if is_ast_substituted_expr."""

        raise UF.CHBError(
            "Property substituted_expr not supported on expr type: " + self.tag)

    @property
    def cast_tgt_type(self) -> str:
        """Applicable only if is_ast_cast_expr."""

        raise UF.CHBError(
            "Property cast_tgt_type not supported on expr type: " + self.tag)

    @property
    def cast_expr(self) -> "ASTExpr":
        """Applicable only if is_cast_expr."""

        raise UF.CHBError(
            "Property cast_expr not supported on expr type: " + self.tag)

    @property
    def op(self) -> str:
        """Applicable only if is_ast_unary_op or is_ast_binary_op."""

        raise UF.CHBError(
            "Property op not supported on expr type: " + self.tag)

    @property
    def exp1(self) -> "ASTExpr":
        """Applicable only if is_ast_unary_op, is_ast_binary_op, or is_ast_question."""

        raise UF.CHBError(
            "Property exp1 not supported on expr type: " + self.tag)

    @property
    def exp2(self) -> "ASTExpr":
        """Applicable only if is_ast_binary_op or is_ast_question."""

        raise UF.CHBError(
            "Property exp2 not supported on expr type: " + self.tag)

    @property
    def exp3(self) -> "ASTExpr":
        """Applicable only if is_ast_question."""

        raise UF.CHBError(
            "Property exp3 not supported on expr type: " + self.tag)

    @abstractmethod
    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        ...

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])


class ASTConstant(ASTExpr):

    def __init__(self, tag: str) -> None:
        ASTExpr.__init__(self, tag)

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

    def __init__(self, cvalue: int, tag: str = "integer-constant") -> None:
        ASTConstant.__init__(self, tag)
        self._cvalue = cvalue

    @property
    def is_integer_constant(self) -> bool:
        return True

    @property
    def cvalue(self) -> int:
        return self._cvalue

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_integer_constant(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_integer_constant(self)

    def use(self) -> List[str]:
        return []

    def to_c_like(self, sp: int = 0) -> str:
        if self.cvalue > 100000:
            return hex(self.cvalue)
        else:
            return str(self.cvalue)

    def to_string(self, sp: int = 0) -> str:
        return ASTNode.to_string(self, sp) + "(" + str(self.cvalue) + ")"

    def __str__(self) -> str:
        return str(self.cvalue)


class ASTGlobalAddressConstant(ASTIntegerConstant):
    """An integer constant that is the address of a global variable."""

    def __init__(self, cvalue: int, addressexpr: "ASTExpr") -> None:
        ASTIntegerConstant.__init__(self, cvalue, tag="global-address")
        self._addressexpr = addressexpr

    @property
    def is_global_address(self) -> bool:
        return True

    @property
    def address_expr(self) -> "ASTExpr":
        return self._addressexpr

    @property
    def is_ast_lval_expr(self) -> bool:
        return self.address_expr.is_ast_lval_expr

    @property
    def lval(self) -> "ASTLval":
        return self.address_expr.lval

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_global_address(self)

    def transformer(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_global_address(self)

    @property
    def address_tgt_type(self) -> Optional["BCTyp"]:
        if self.address_expr.is_ast_addressof:
            expr = cast("ASTAddressOf", self.address_expr)
            lval = expr.lval
            if expr.lval.is_variable and expr.lval.offset.is_no_offset:
                varinfo = cast("ASTVariable", expr.lval.lhost).varinfo
                return varinfo.vtype
            else:
                return None
        else:
            return None
    @property
    def ctype(self) -> Optional["BCTyp"]:
        return self.address_expr.ctype

    def to_c_like(self, sp: int = 0) -> str:
        return self.address_expr.to_c_like()

    def __str__(self) -> str:
        return str(self.address_expr)


class ASTStringConstant(ASTConstant):

    def __init__(self, expr: "ASTExpr", cstr: str, saddr: str) -> None:
        ASTConstant.__init__(self, "string-constant")
        self._expr = expr    # expression that produced the string
        self._cstr = cstr
        self._saddr = saddr

    @property
    def is_string_constant(self) -> bool:
        return True
        
    @property
    def address_expr(self) -> "ASTExpr":
        return self._expr

    @property
    def cstr(self) -> str:
        return self._cstr

    @property
    def string_address(self) -> str:
        return self._saddr

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_string_constant(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_string_constant(self)

    def use(self) -> List[str]:
        return []

    def to_c_like(self, sp: int = 0) -> str:
        return '"' + self.cstr + '"'

    def to_string(self, sp: int = 0) -> str:
        return ASTNode.to_string(self, sp) + "(" + self.cstr + ")"

    def __str__(self) -> str:
        return '"' + self.cstr + '"'


class ASTLvalExpr(ASTExpr):

    def __init__(self, lval: "ASTLval", tag: str = "lval-expr") -> None:
        ASTExpr.__init__(self, tag)
        self._lval = lval

    @property
    def is_ast_lval_expr(self) -> bool:
        return True

    @property
    def lval(self) -> "ASTLval":
        return self._lval

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_lval_expression(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_lval_expression(self)

    @property
    def ctype(self) -> Optional["BCTyp"]:
        return self.lval.ctype

    def address_taken(self) -> Set[str]:
        return self.lval.address_taken()

    def variables_used(self) -> Set[str]:
        return self.lval.variables_used()

    def use(self) -> List[str]:
        return self.lval.use()

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
    """An expression that was substituted for an lvalue-expression (rhs).

    This expression subtype is introduced to keep track of provenance. Its use
    is mostly transparent w.r.t. to other properties, in the sense that all
    properties and methods are directly delegated to the substituted expression.

    In particular, the visitor and transformer are delegated to the substituted 
    expression. The transformer re-assembles the substituted expression.
    """

    def __init__(self, lval: "ASTLval", assign_id: int, expr: "ASTExpr") -> None:
        ASTLvalExpr.__init__(self, lval, tag="substituted-expr")
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
    def super_lval(self) -> "ASTLval":
        """Return the lval from the original instruction.

        Note: requires type:ignore because of a bug in mypy.
        """

        return ASTLvalExpr.lval.fget(self) # type:ignore

    def accept(self, visitor: "ASTVisitor") -> None:
        self.substituted_expr.accept(visitor)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return ASTSubstitutedExpr(
            # get the lval from the super class (but in mypy requires ignore)
            ASTLvalExpr.lval.fget(self), # type:ignore
            self.assign_id,
            cast("ASTExpr", self.substituted_expr.transform(transformer)))

    @property
    def is_ast_constant(self) -> bool:
        return self.substituted_expr.is_ast_constant

    @property
    def is_integer_constant(self) -> bool:
        return self.substituted_expr.is_integer_constant

    @property
    def is_global_address(self) -> bool:
        return self.substituted_expr.is_global_address

    @property
    def address_expr(self) -> "ASTExpr":
        return self.substituted_expr.address_expr

    @property
    def is_string_constant(self) -> bool:
        return self.substituted_expr.is_string_constant

    @property
    def is_ast_lval_expr(self) -> bool:
        """Note: this property is overridden from its super class."""
        
        return self.substituted_expr.is_ast_lval_expr

    @property
    def lval(self) -> "ASTLval":
        """Note: this property is overridden from its super class."""
        
        return self.substituted_expr.lval

    @property
    def cvalue(self) -> int:
        if self.is_integer_constant:
            return self.substituted_expr.cvalue
        else:
            raise Exception("Internal error in substituted expression")

    @property
    def ctype(self) -> Optional["BCTyp"]:
        return self.substituted_expr.ctype

    @property
    def is_ast_addressof(self) -> bool:
        return self.substituted_expr.is_ast_addressof

    def variables_used(self) -> Set[str]:
        return self.substituted_expr.variables_used()

    def address_taken(self) -> Set[str]:
        return self.substituted_expr.address_taken()

    def use(self) -> List[str]:
        return self.substituted_expr.use()

    def to_c_like(self, sp: int = 0) -> str:
        return self.substituted_expr.to_c_like()

    def __str__(self) -> str:
        return str(self.substituted_expr)


class ASTCastE(ASTExpr):

    def __init__(self, tgttyp: str, exp: "ASTExpr") -> None:
        ASTExpr.__init__(self, "cast-expr")
        self._tgttyp = tgttyp
        self._exp = exp

    @property
    def is_ast_cast_expr(self) -> bool:
        return True

    @property
    def cast_tgt_type(self) -> str:
        return self._tgttyp

    @property
    def cast_expr(self) -> "ASTExpr":
        return self._exp

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_cast_expression(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_cast_expression(self)

    def address_taken(self) -> Set[str]:
        return self.cast_expr.address_taken()

    def variables_used(self) -> Set[str]:
        return self.cast_expr.variables_used()

    def use(self) -> List[str]:
        return self.cast_expr.use()

    def to_c_like(self, sp: int = 0) -> str:
        return "(" + str(self.cast_tgt_type) + ")" + self.cast_expr.to_c_like()

    def __str__(self) -> str:
        return "((" + str(self.cast_tgt_type) + ")" + str(self.cast_expr) + ")"


class ASTUnaryOp(ASTExpr):

    def __init__(self, op: str,  exp: "ASTExpr") -> None:
        ASTExpr.__init__(self, "unary-op")
        self._op = op
        self._exp = exp

    @property
    def is_ast_unary_op(self) -> bool:
        return True

    @property
    def op(self) -> str:
        return self._op

    @property
    def exp1(self) -> "ASTExpr":
        return self._exp

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_unary_expression(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_unary_expression(self)

    def address_taken(self) -> Set[str]:
        return self.exp1.address_taken()

    def variables_used(self) -> Set[str]:
        return self.exp1.variables_used()

    def use(self) -> List[str]:
        return self.exp1.use()

    def to_c_like(self, sp: int = 0) -> str:
        return operators[self.op] + self.exp1.to_c_like()

    def __str__(self) -> str:
        return "(" + operators[self.op] + str(self.exp1) + ")"


class ASTBinaryOp(ASTExpr):

    def __init__(
            self,
            op: str,
            exp1: "ASTExpr",
            exp2: "ASTExpr") -> None:
        ASTExpr.__init__(self, "binary-op")
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

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_binary_expression(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_binary_expression(self)

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
            exp1: "ASTExpr",
            exp2: "ASTExpr",
            exp3: "ASTExpr") -> None:
        ASTExpr.__init__(self, "question")
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

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_question_expression(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_question_expression(self)

    def address_taken(self) -> Set[str]:
        return self.exp1.address_taken().union(
            self.exp2.address_taken()).union(self.exp3.address_taken())

    def variables_used(self) -> Set[str]:
        return self.exp1.variables_used().union(
            self.exp2.variables_used()).union(self.exp3.variables_used())

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

    def __init__(self, lval: "ASTLval") -> None:
        ASTExpr.__init__(self, "address-of")
        self._lval = lval

    @property
    def is_ast_addressof(self) -> bool:
        return True

    @property
    def lval(self) -> "ASTLval":
        return self._lval

    @property
    def address_tgt_type(self) -> Optional["BCTyp"]:
        return self.lval.ctype

    @property
    def ctype(self) -> Optional["BCTyp"]:
        if self.lval.lhost.is_variable:
            if self.lval.lhost.ctype is not None:
                if self.lval.lhost.ctype.is_array:
                    if self.lval.offset.is_index_offset:
                        indexoffset = cast(
                            "ASTIndexOffset", self.lval.offset)
                        if indexoffset.index.is_integer_constant:
                            index = cast(
                                "ASTIntegerConstant", indexoffset.index)
                            if index.cvalue == 0:
                                return self.lval.lhost.ctype
                            

        return None

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_address_of_expression(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_address_of_expression(self)

    def address_taken(self) -> Set[str]:
        return set([str(self.lval)])

    def variables_used(self) -> Set[str]:
        return set([str(self.lval)])

    def use(self) -> List[str]:
        return [str(self.lval)]

    def to_string(self, sp: int = 0) -> str:
        lines: List[str] = []
        lines.append(ASTNode.to_string(self, sp))
        lines.append(self.lval.to_string(sp + 2))
        return "\n".join(lines)

    def to_c_like(self, sp: int = 0) -> str:
        return "&" + self.lval.to_c_like()

    def __str__(self) -> str:
        return "&(" + str(self.lval) + ")"
