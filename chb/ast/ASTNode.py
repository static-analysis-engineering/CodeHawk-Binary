# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs LLC
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

The structure is based on CIL (ref https://people.eecs.berkeley.edu/~necula/cil/).
"""

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


if TYPE_CHECKING:
    from chb.ast.ASTCTyper import ASTCTyper
    from chb.ast.ASTIndexer import ASTIndexer
    from chb.ast.ASTTransformer import ASTTransformer
    from chb.ast.ASTVisitor import ASTVisitor


c_indent = 3

"""
Names used in relation to CIL sum types:

Unary operators:
 Neg: "neg"
 BNot: "bnot"
 LNot: "lnot"

Binary operators:
 PlusA: "plus"
 PlusPI: "plus"
 IndexPI: "plus"
 MinusA: "minus"
 MinusPI: "minus"
 MinusPP: "minus"
 Mult: "mult"
 Div: "div"
 Mod: "mod"
 Shiftlt: "lsl",
 Shiftrt: "lsr", "asr"
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
    "asr": " >> ",   # arithmetic shift right
    "band": " & ",   # bitwise and
    "bnot": "~",     # bitwise not
    "bor": " | ",    # bitwise or
    "bxor": " ^ ",   # bitwise xor
    "div": " / ",    # integer division
    "eq": " == ",    # equal
    "ge": " >= ",    # greater than or equal to
    "gt": " > ",     # greater than
    "land": " && ",  # logical and
    "le": " <= ",    # less than or equal to
    "lnot": " ! ",   # logical not
    "lor": " || ",   # logical or
    "lsl": " << ",   # logical shift left
    "lsr": " >> ",   # logical shift right; need to infer type as unsigned
    "lt": " < ",     # less than
    "minus": " - ",
    "mod": " % ",    # modulo
    "mult": " * ",   # multiplication
    "ne": " != ",    # not equal
    "neg": " -",     # unary minus
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

    @abstractmethod
    def index(self, indexer: "ASTIndexer") -> int:
        ...

    @abstractmethod
    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        ...

    @property
    def is_ast_stmt(self) -> bool:
        return False

    @property
    def is_stmt_label(self) -> bool:
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

    @property
    def is_varinfo(self) -> bool:
        return False

    @property
    def is_compinfo(self) -> bool:
        return False

    @property
    def is_enuminfo(self) -> bool:
        return False

    def variables_used(self) -> Set[str]:
        return set([])

    def callees(self) -> Set[str]:
        return set([])

    def __str__(self) -> str:
        return self.tag


class ASTStmt(ASTNode):

    def __init__(
            self,
            stmtid: int,
            locationid: int,
            labels: List["ASTStmtLabel"],
            tag: str) -> None:
        ASTNode.__init__(self, tag)
        self._stmtid = stmtid
        self._locationid = locationid
        self._labels = labels.copy()   # avoid unwanted aliasing

    @property
    def stmtid(self) -> int:
        return self._stmtid

    @property
    def locationid(self) -> int:
        return self._locationid

    @property
    def labels(self) -> List["ASTStmtLabel"]:
        return self._labels

    def add_label(self, name: str) -> None:
        self._labels.append(ASTLabel(self.locationid, name))

    @property
    def is_ast_stmt(self) -> bool:
        return True

    @property
    def is_ast_return(self) -> bool:
        return False

    @property
    def is_ast_break(self) -> bool:
        return False

    @property
    def is_ast_continue(self) -> bool:
        return False

    @property
    def is_ast_goto(self) -> bool:
        return False

    @property
    def is_ast_loop(self) -> bool:
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
    def accept(self, visitor: "ASTVisitor") -> None:
        ...

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


class ASTReturn(ASTStmt):

    def __init__(
            self,
            stmtid: int,
            locationid: int,
            expr: Optional["ASTExpr"],
            labels: List["ASTStmtLabel"] = []) -> None:
        ASTStmt.__init__(self, stmtid, locationid, labels, "return")
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

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_return_stmt(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_return_stmt(self)

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


class ASTBreak(ASTStmt):

    def __init__(
            self,
            stmtid: int,
            locationid: int,
            labels: List["ASTStmtLabel"] = []) -> None:
        ASTStmt.__init__(self, stmtid, locationid, labels, "break")

    @property
    def is_ast_break(self) -> bool:
        return True

    def accept(self, visitor: "ASTVisitor") -> None:
        return visitor.visit_break_stmt(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        return transformer.transform_break_stmt(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_break_stmt(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_break_stmt(self)


class ASTContinue(ASTStmt):

    def __init__(
            self,
            stmtid: int,
            locationid: int,
            labels: List["ASTStmtLabel"] = []) -> None:
        ASTStmt.__init__(self, stmtid, locationid, labels, "continue")

    @property
    def is_ast_continue(self) -> bool:
        return True

    def accept(self, visitor: "ASTVisitor") -> None:
        return visitor.visit_continue_stmt(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        return transformer.transform_continue_stmt(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_continue_stmt(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_continue_stmt(self)


class ASTLoop(ASTStmt):

    def __init__(
            self,
            stmtid: int,
            locationid: int,
            breakaddr: Optional[str],
            continueaddr: Optional[str],
            body: "ASTStmt") -> None:
        ASTStmt.__init__(self, stmtid, locationid, [], "loop")
        self._body = body
        self._breakaddr = breakaddr
        self._continueaddr = continueaddr

    @property
    def is_ast_loop(self) -> bool:
        return True

    @property
    def body(self) -> "ASTStmt":
        return self._body

    @property
    def breakaddr(self) -> Optional[str]:
        return self._breakaddr

    @property
    def continueaddr(self) -> Optional[str]:
        return self._continueaddr

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_loop_stmt(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        return transformer.transform_loop_stmt(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_loop_stmt(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_loop_stmt(self)

    def is_empty(self) -> bool:
        return self.body.is_empty()

    def address_taken(self) -> Set[str]:
        return self.body.address_taken()

    def variables_used(self) -> Set[str]:
        return self.body.variables_used()

    def callees(self) -> Set[str]:
        return self.body.callees()

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append(ASTNode.__str__(self))
        lines.append(str(self.body))
        return "\n".join(lines)


class ASTBlock(ASTStmt):

    def __init__(
            self,
            stmtid: int,
            locationid: int,
            stmts: List["ASTStmt"],
            labels: List["ASTStmtLabel"] = []) -> None:
        ASTStmt.__init__(self, stmtid, locationid, labels, "block")
        self._stmts = stmts

    @property
    def is_ast_block(self) -> bool:
        return True

    @property
    def stmts(self) -> List["ASTStmt"]:
        return self._stmts

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_block_stmt(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        return transformer.transform_block_stmt(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_block_stmt(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_block_stmt(self)

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

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append(ASTNode.__str__(self))
        lines.append("\n".join(str(s) for s in self.stmts))
        return "\n".join(lines)


class ASTInstrSequence(ASTStmt):

    def __init__(
            self,
            stmtid: int,
            locationid: int,
            instrs: List["ASTInstruction"],
            labels: List["ASTStmtLabel"] = []) -> None:
        ASTStmt.__init__(self, stmtid, locationid, labels, "instrs")
        self._instrs: List["ASTInstruction"] = instrs
        self._aexp: Dict[int, List["ASTExpr"]] = {}

    @property
    def is_ast_instruction_sequence(self) -> bool:
        return True

    @property
    def instructions(self) -> List["ASTInstruction"]:
        return self._instrs

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_instruction_sequence_stmt(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        return transformer.transform_instruction_sequence_stmt(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_instruction_sequence_stmt(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_instruction_sequence_stmt(self)

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

    def __str__(self) -> str:
        return "\n".join(str(i) for i in self.instructions)


class ASTBranch(ASTStmt):

    def __init__(
            self,
            stmtid: int,
            locationid: int,
            cond: "ASTExpr",
            ifstmt: "ASTStmt",
            elsestmt: "ASTStmt",
            tgtaddress: str,
            mergeaddress: Optional[str],
            labels: List["ASTStmtLabel"] = []) -> None:
        ASTStmt.__init__(self, stmtid, locationid, labels, "if")
        self._cond = cond
        self._ifstmt = ifstmt
        self._elsestmt = elsestmt
        self._tgtaddress = tgtaddress
        self._mergeaddress = mergeaddress

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
    def target_address(self) -> str:
        return self._tgtaddress

    @property
    def merge_address(self) -> Optional[str]:
        return self._mergeaddress

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_branch_stmt(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        return transformer.transform_branch_stmt(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_branch_stmt(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_branch_stmt(self)

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


class ASTGoto(ASTStmt):

    def __init__(
            self,
            stmtid: int,
            locationid: int,
            destinationlabel: str,
            destinationaddr: str,
            labels: List["ASTStmtLabel"] = []) -> None:
        ASTStmt.__init__(self, stmtid, locationid, labels, "goto")
        self._destinationlabel = destinationlabel
        self._destinationaddr = destinationaddr

    @property
    def destination(self) -> str:
        return self._destinationlabel

    @property
    def destination_address(self) -> str:
        return self._destinationaddr

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_goto_stmt(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        return transformer.transform_goto_stmt(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_goto_stmt(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_goto_stmt(self)


class ASTComputedGoto(ASTStmt):

    def __init__(
            self,
            stmtid: int,
            locationid: int,
            tgtexpr: "ASTExpr",
            labels: List["ASTStmtLabel"] = []) -> None:
        ASTStmt.__init__(self, stmtid, locationid, labels, "computedgoto")
        self._tgtexpr = tgtexpr

    @property
    def target_expr(self) -> "ASTExpr":
        return self._tgtexpr

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_computedgoto_stmt(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        return transformer.transform_computedgoto_stmt(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_computedgoto_stmt(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_computedgoto_stmt(self)


class ASTSwitchStmt(ASTStmt):

    def __init__(
            self,
            stmtid: int,
            locationid: int,
            switchexpr: "ASTExpr",
            cases: "ASTStmt",
            mergeaddr: Optional[str] = None,
            labels: List["ASTStmtLabel"] = []) -> None:
        ASTStmt.__init__(self, stmtid, locationid, labels, "switch")
        self._switchexpr = switchexpr
        self._cases = cases
        self._mergeaddress = mergeaddr

    @property
    def switchexpr(self) -> "ASTExpr":
        return self._switchexpr

    @property
    def cases(self) -> "ASTStmt":
        return self._cases

    @property
    def merge_address(self) -> Optional[str]:
        return self._mergeaddress

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_switch_stmt(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmt":
        return transformer.transform_switch_stmt(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_switch_stmt(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_switch_stmt(self)


class ASTStmtLabel(ASTNode, ABC):

    def __init__(self, locationid: int, tag: str) -> None:
        ASTNode.__init__(self, tag)
        self._locationid = locationid

    @property
    def is_stmt_label(self) -> bool:
        return True

    @property
    def locationid(self) -> int:
        return self._locationid

    @property
    def is_ast_instruction_sequence(self) -> bool:
        return False


class ASTLabel(ASTStmtLabel):

    def __init__(self, locationid: int, name: str) -> None:
        assert len(name) > 0
        assert name[0] not in "0123456789", "C label names cannot start with a digit"
        ASTStmtLabel.__init__(self, locationid, "label")
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_label(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmtLabel":
        return transformer.transform_label(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_label(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_label(self)


class ASTCaseLabel(ASTStmtLabel):

    def __init__(self, locationid: int, expr: "ASTExpr") -> None:
        ASTStmtLabel.__init__(self, locationid, "case")
        self._expr = expr

    @property
    def case_expr(self) -> "ASTExpr":
        return self._expr

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_case_label(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmtLabel":
        return transformer.transform_case_label(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_case_label(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_case_label(self)


class ASTCaseRangeLabel(ASTStmtLabel):

    def __init__(
            self,
            locationid: int,
            lowexpr: "ASTExpr",
            highexpr: "ASTExpr") -> None:
        ASTStmtLabel.__init__(self, locationid, "caserange")
        self._lowexpr = lowexpr
        self._highexpr = highexpr

    @property
    def lowexpr(self) -> "ASTExpr":
        return self._lowexpr

    @property
    def highexpr(self) -> "ASTExpr":
        return self._highexpr

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_case_range_label(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmtLabel":
        return transformer.transform_case_range_label(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_case_range_label(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_case_range_label(self)


class ASTDefaultLabel(ASTStmtLabel):

    def __init__(self, locationid: int) -> None:
        ASTStmtLabel.__init__(self, locationid, "default")

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_default_label(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTStmtLabel":
        return transformer.transform_default_label(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_default_label(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_default_label(self)


class ASTInstruction(ASTNode, ABC):

    def __init__(self, instrid: int, locationid: int, tag: str) -> None:
        ASTNode.__init__(self, tag)
        self._instrid = instrid
        self._locationid = locationid

    @property
    def instrid(self) -> int:
        return self._instrid

    @property
    def locationid(self) -> int:
        return self._locationid

    @property
    def is_ast_instruction(self) -> bool:
        return True

    @property
    def is_ast_assign(self) -> bool:
        return False

    @property
    def is_ast_call(self) -> bool:
        return False

    @property
    def is_ast_nop(self) -> bool:
        return False

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


class ASTNOPInstruction(ASTInstruction):
    """Instruction without semantic content to hold location information."""

    def __init__(
            self,
            instrid: int,
            locationid: int,
            descr: str) -> None:
        ASTInstruction.__init__(self, instrid, locationid, "nop")
        self._descr = descr

    @property
    def description(self) -> str:
        return self._descr

    @property
    def is_ast_nop(self) -> bool:
        return True

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_nop_instr(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTInstruction":
        return transformer.transform_nop_instr(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_nop_instr(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_nop_instr(self)

    def __str__(self) -> str:
        return "NOP:" + self.description



class ASTAssign(ASTInstruction):

    def __init__(
            self,
            instrid: int,
            locationid: int,
            lhs: "ASTLval",
            rhs: "ASTExpr") -> None:
        ASTInstruction.__init__(self, instrid, locationid, "assign")
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

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_assign_instr(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTInstruction":
        return transformer.transform_assign_instr(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_assign_instr(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_assign_instr(self)

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

    def __str__(self) -> str:
        return str(self.lhs) + " := " + str(self.rhs)


class ASTCall(ASTInstruction):

    def __init__(
            self,
            instrid: int,
            locationid: int,
            lhs: Optional["ASTLval"],
            tgt: "ASTExpr",
            args: List["ASTExpr"]) -> None:
        ASTInstruction.__init__(self, instrid, locationid, "call")
        self._lhs = lhs
        self._tgt = tgt
        self._args = args

    @property
    def is_ast_call(self) -> bool:
        return True

    @property
    def lhs(self) -> Optional["ASTLval"]:
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

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_call_instr(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_call_instr(self)

    def __str__(self) -> str:
        result = ""
        if self.lhs is not None:
            result += (str(self.lhs) + " = ")
        result += str(self.tgt)
        result += "("
        result += ", ".join(str(a) for a in self.arguments)
        result += ")"
        return result


class ASTAsm(ASTInstruction):

    def __init__(
            self,
            instrid: int,
            locationid: int,
            vola: bool,
            templates: List[str],
            clobbers: List[str]) -> None:
        ASTInstruction.__init__(self, instrid, locationid, "asm")
        self._volatile = vola
        self._templates = templates
        self._clobbers = clobbers

    @property
    def is_ast_asm(self) -> bool:
        return True

    @property
    def volatile(self) -> bool:
        return self._volatile

    @property
    def template(self) -> str:
        return " ".join(self._templates)

    @property
    def clobbers(self) -> str:
        return " ".join(self._clobbers)

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_asm_instr(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTInstruction":
        return transformer.transform_asm_instr(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_asm_instr(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_asm_instr(self)

    def __str__(self) -> str:
        vol = " volatile" if self.volatile else ""
        return "asm{}({}, {})".format(vol, self.template, self.clobbers) 


class ASTLval(ASTNode):

    def __init__(
            self, lvalid: int, lhost: "ASTLHost", offset: "ASTOffset") -> None:
        ASTNode.__init__(self, "lval")
        self._lvalid = lvalid
        self._lhost = lhost
        self._offset = offset

    @property
    def is_ast_lval(self) -> bool:
        return True

    @property
    def lvalid(self) -> int:
        return self._lvalid

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

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_lval(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_lval(self)

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

    def use(self) -> List[str]:
        return self.lhost.use() + self.offset.use()

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

    @abstractmethod
    def transform(self, transformer: "ASTTransformer") -> "ASTLHost":
        ...

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])


class ASTVarInfo(ASTNode):

    def __init__(
            self,
            vname: str,
            vtype: Optional["ASTTyp"],
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None) -> None:
        ASTNode.__init__(self, "varinfo")
        self._vname = vname
        self._vtype = vtype
        self._parameter = parameter
        self._globaladdress = globaladdress
        self._vdescr = vdescr  # describes what the variable holds

    @property
    def vname(self) -> str:
        return self._vname

    @property
    def vtype(self) -> Optional["ASTTyp"]:
        return self._vtype

    @vtype.setter
    def vtype(self, new_type: "ASTTyp") -> None:
        self._vtype = new_type

    @property
    def parameter(self) -> Optional[int]:
        return self._parameter

    @property
    def globaladdress(self) -> Optional[int]:
        return self._globaladdress

    @property
    def vdescr(self) -> Optional[str]:
        return self._vdescr

    @vdescr.setter
    def vdescr(self, new_descr: str) -> None:
        self._vdescr = new_descr

    @property
    def is_varinfo(self) -> bool:
        return True

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_varinfo(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTVarInfo":
        return transformer.transform_varinfo(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_varinfo(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_varinfo(self)

    def __str__(self) -> str:
        return self.vname


class ASTVariable(ASTLHost):

    def __init__(self, vinfo: "ASTVarInfo") -> None:
        ASTLHost.__init__(self, "var")
        self._vinfo = vinfo

    @property
    def is_variable(self) -> bool:
        return True

    @property
    def varinfo(self) -> "ASTVarInfo":
        return self._vinfo

    @property
    def vname(self) -> str:
        return self.varinfo.vname

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_variable(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTLHost":
        return transformer.transform_variable(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_variable(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_variable(self)

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([self.vname])

    def use(self) -> List[str]:
        if self.vname == "PC":
            return []
        else:
            return [self.vname]

    def __str__(self) -> str:
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

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_memref(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_memref(self)

    def address_taken(self) -> Set[str]:
        return self.memexp.address_taken()

    def variables_used(self) -> Set[str]:
        return self.memexp.variables_used()

    def use(self) -> List[str]:
        return self.memexp.use()

    def __str__(self) -> str:
        return "*" + str(self.memexp)


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

    @property
    def offset(self) -> "ASTOffset":
        raise Exception("offset property not supported for " + str(self))

    @abstractmethod
    def transform(self, transformer: "ASTTransformer") -> "ASTOffset":
        ...

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

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_no_offset(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_no_offset(self)

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])

    def __str__(self) -> str:
        return ""


class ASTFieldOffset(ASTOffset):

    def __init__(
            self,
            fieldname: str,
            compkey: int,
            byteoffset: "ASTOffset") -> None:
        ASTOffset.__init__(self, "field-offset")
        self._fieldname = fieldname
        self._compkey = compkey
        self._byteoffset = byteoffset

    @property
    def is_field_offset(self) -> bool:
        return True

    @property
    def fieldname(self) -> str:
        return self._fieldname

    @property
    def compkey(self) -> int:
        return self._compkey

    @property
    def offset(self) -> "ASTOffset":
        return self._byteoffset

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_field_offset(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTOffset":
        return transformer.transform_field_offset(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_field_offset(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_field_offset(self)

    def address_taken(self) -> Set[str]:
        return self.offset.address_taken()

    def variables_used(self) -> Set[str]:
        return self.offset.variables_used()

    def use(self) -> List[str]:
        return self.offset.use()

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
    def index_expr(self) -> "ASTExpr":
        return self._index

    @property
    def offset(self) -> "ASTOffset":
        return self._offset

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_index_offset(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTOffset":
        return transformer.transform_index_offset(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_index_offset(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_index_offset(self)

    '''
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
    '''

    def address_taken(self) -> Set[str]:
        return self.index_expr.address_taken().union(self.offset.address_taken())

    def variables_used(self) -> Set[str]:
        return self.index_expr.variables_used().union(self.offset.variables_used())

    def use(self) -> List[str]:
        return self.index_expr.use() + self.offset.use()

    def __str__(self) -> str:
        return "[" + str(self.index_expr) + "]" + str(self.offset)


class ASTExpr(ASTNode):
    """Universal interface to all expression types.

    This class presents the union of properties and methods for all subclasses,
    but calls will fail (or return None in case of an optional returntype) on
    those properties and methods not supported for the subclass they are called
    on.

    This approach requires checking the subclass with the is_... property, but
    avoids the need for subsequent explicit casting (for type checking).
    """

    def __init__(self, exprid: int, tag: str) -> None:
        ASTNode.__init__(self, tag)
        self._exprid = exprid

    @property
    def exprid(self) -> int:
        return self._exprid

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

    @abstractmethod
    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        ...

    @abstractmethod
    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        ...

    def use(self) -> List[str]:
        return []

    def address_taken(self) -> Set[str]:
        return set([])

    def variables_used(self) -> Set[str]:
        return set([])


class ASTConstant(ASTExpr):

    def __init__(self, exprid: int, tag: str) -> None:
        ASTExpr.__init__(self, exprid, tag)

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

    def __init__(
            self,
            exprid: int,
            cvalue: int,
            ikind: str = "iint",
            tag: str = "integer-constant") -> None:
        ASTConstant.__init__(self, exprid, tag)
        self._cvalue = cvalue
        self._ikind = ikind

    @property
    def is_integer_constant(self) -> bool:
        return True

    @property
    def cvalue(self) -> int:
        return self._cvalue

    @property
    def ikind(self) -> str:
        return self._ikind

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_integer_constant(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_integer_constant(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_integer_constant(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_integer_constant(self)

    def use(self) -> List[str]:
        return []

    def __str__(self) -> str:
        return str(self.cvalue)


class ASTGlobalAddressConstant(ASTIntegerConstant):
    """An integer constant that is the address of a global variable."""

    def __init__(self, exprid: int, cvalue: int, addressexpr: "ASTExpr") -> None:
        ASTIntegerConstant.__init__(self, exprid, cvalue, tag="global-address")
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

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_global_address(self)

    def transformer(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_global_address(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_global_address(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_global_address(self)

    def __str__(self) -> str:
        return str(self.address_expr)


class ASTFloatingPointConstant(ASTConstant):

    def __init__(
            self,
            exprid: int,
            fvalue: float,
            fkind: str = "float",
            tag: str = "fp-constant") -> None:
        ASTConstant.__init__(self, exprid, tag)
        self._fvalue = fvalue
        self._fkind = fkind

    @property
    def is_floating_point_constant(self) -> bool:
        return True

    @property
    def fvalue(self) -> float:
        return self._fvalue

    @property
    def fkind(self) -> str:
        return self._fkind

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_floating_point_constant(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_floating_point_constant(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_floating_point_constant(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_floating_point_constant(self)

    def __str__(self) -> str:
        return str(self.fvalue)


class ASTStringConstant(ASTConstant):

    def __init__(
            self,
            exprid: int,
            expr: Optional["ASTExpr"],
            cstr: str,
            saddr: Optional[str]) -> None:
        ASTConstant.__init__(self, exprid, "string-constant")
        self._expr = expr    # expression that produced the string
        self._cstr = cstr
        self._saddr = saddr

    @property
    def is_string_constant(self) -> bool:
        return True

    @property
    def address_expr(self) -> Optional["ASTExpr"]:
        return self._expr

    @property
    def cstr(self) -> str:
        return self._cstr

    @property
    def string_address(self) -> Optional[str]:
        return self._saddr

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_string_constant(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_string_constant(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_string_constant(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_string_constant(self)

    def use(self) -> List[str]:
        return []

    def __str__(self) -> str:
        return '"' + self.cstr + '"'


class ASTLvalExpr(ASTExpr):

    def __init__(self, exprid: int, lval: "ASTLval", tag: str = "lval-expr") -> None:
        ASTExpr.__init__(self, exprid, tag)
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

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_lval_expression(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_lval_expression(self)

    def address_taken(self) -> Set[str]:
        return self.lval.address_taken()

    def variables_used(self) -> Set[str]:
        return self.lval.variables_used()

    def use(self) -> List[str]:
        return self.lval.use()

    def __str__(self) -> str:
        return str(self.lval)


class ASTSizeOfExpr(ASTExpr):

    def __init__(self, exprid: int, tgttyp: "ASTTyp") -> None:
        ASTExpr.__init__(self, exprid, "sizeof-expr")
        self._tgttyp = tgttyp

    @property
    def tgt_type(self) -> "ASTTyp":
        return self._tgttyp

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_sizeof_expression(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_sizeof_expression(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_sizeof_expression(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_sizeof_expression(self)

    def __str__(self) -> str:
        return "sizeof(" + str(self.tgt_type) + ")"


class ASTCastExpr(ASTExpr):

    def __init__(self, exprid: int, tgttyp: "ASTTyp", exp: "ASTExpr") -> None:
        ASTExpr.__init__(self, exprid, "cast-expr")
        self._tgttyp = tgttyp
        self._exp = exp

    @property
    def is_ast_cast_expr(self) -> bool:
        return True

    @property
    def cast_tgt_type(self) -> "ASTTyp":
        return self._tgttyp

    @property
    def cast_expr(self) -> "ASTExpr":
        return self._exp

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_cast_expression(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_cast_expression(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_cast_expression(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_cast_expression(self)

    def address_taken(self) -> Set[str]:
        return self.cast_expr.address_taken()

    def variables_used(self) -> Set[str]:
        return self.cast_expr.variables_used()

    def use(self) -> List[str]:
        return self.cast_expr.use()

    def __str__(self) -> str:
        return "((" + str(self.cast_tgt_type) + ")" + str(self.cast_expr) + ")"


class ASTUnaryOp(ASTExpr):

    def __init__(self, exprid: int, op: str,  exp: "ASTExpr") -> None:
        ASTExpr.__init__(self, exprid, "unary-op")
        if op not in operators:
            raise Exception("Unary operator " + op + " not recognized")
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

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_unary_expression(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_unary_expression(self)

    def address_taken(self) -> Set[str]:
        return self.exp1.address_taken()

    def variables_used(self) -> Set[str]:
        return self.exp1.variables_used()

    def use(self) -> List[str]:
        return self.exp1.use()

    def __str__(self) -> str:
        return "(" + operators[self.op] + str(self.exp1) + ")"


class ASTBinaryOp(ASTExpr):

    def __init__(
            self,
            exprid: int,
            op: str,
            exp1: "ASTExpr",
            exp2: "ASTExpr") -> None:
        ASTExpr.__init__(self, exprid, "binary-op")
        if op not in operators:
            raise Exception("Binary operator " + op + " not recognized")
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

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_binary_expression(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_binary_expression(self)

    @property
    def is_integer_constant(self) -> bool:
        return (
            self.exp1.is_integer_constant
            and self.exp2.is_integer_constant
            and self.op in ["plus", "minus"])

    def address_taken(self) -> Set[str]:
        return self.exp1.address_taken().union(self.exp2.address_taken())

    def variables_used(self) -> Set[str]:
        return self.exp1.variables_used().union(self.exp2.variables_used())

    def use(self) -> List[str]:
        return self.exp1.use() + self.exp2.use()

    def __str__(self) -> str:
        return "(" + str(self.exp1) + operators[self.op] + str(self.exp2) + ")"


class ASTQuestion(ASTExpr):

    def __init__(
            self,
            exprid: int,
            exp1: "ASTExpr",
            exp2: "ASTExpr",
            exp3: "ASTExpr") -> None:
        ASTExpr.__init__(self, exprid, "question")
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

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_question_expression(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_question_expression(self)

    def address_taken(self) -> Set[str]:
        return self.exp1.address_taken().union(
            self.exp2.address_taken()).union(self.exp3.address_taken())

    def variables_used(self) -> Set[str]:
        return self.exp1.variables_used().union(
            self.exp2.variables_used()).union(self.exp3.variables_used())

    def __str__(self) -> str:
        return (
            "("
            + str(self.exp1)
            + " ? "
            + str(self.exp2)
            + " : "
            + str(self.exp3)
            + ")")


class ASTAddressOf(ASTExpr):

    def __init__(self, exprid: int, lval: "ASTLval") -> None:
        ASTExpr.__init__(self, exprid, "address-of")
        self._lval = lval

    @property
    def is_ast_addressof(self) -> bool:
        return True

    @property
    def lval(self) -> "ASTLval":
        return self._lval

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_address_of_expression(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTExpr":
        return transformer.transform_address_of_expression(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_address_of_expression(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_address_of_expression(self)

    def address_taken(self) -> Set[str]:
        return set([str(self.lval)])

    def variables_used(self) -> Set[str]:
        return set([str(self.lval)])

    def use(self) -> List[str]:
        return [str(self.lval)]

    def __str__(self) -> str:
        return "&(" + str(self.lval) + ")"


class ASTTyp(ASTNode):

    def __init__(self, tag: str) -> None:
        ASTNode.__init__(self, tag)

    @property
    def is_void(self) -> bool:
        return False

    @property
    def is_integer(self) -> bool:
        return False

    @property
    def is_enum(self) -> bool:
        return False

    @property
    def is_float(self) -> bool:
        return False

    @property
    def is_pointer(self) -> bool:
        return False

    @property
    def is_scalar(self) -> bool:
        return (
            self.is_integer
            or self.is_float
            or self.is_pointer
            or self.is_enum
        )

    @property
    def is_function(self) -> bool:
        return False

    @property
    def is_array(self) -> bool:
        return False

    @property
    def is_compound(self) -> bool:
        return False

    @property
    def is_typedef(self) -> bool:
        return False

    def __eq__(self, other: Any) -> bool:
        return super(ASTTyp, self).__eq__(other)


class ASTTypVoid(ASTTyp):

    def __init__(self) -> None:
        ASTTyp.__init__(self, "void")

    @property
    def is_void(self) -> bool:
        return True

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_void_typ(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTTyp":
        return transformer.transform_void_typ(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_void_typ(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_void_typ(self)

    def __str__(self) -> str:
        return "void"

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ASTTypVoid):
            return False
        return True


class ASTTypInt(ASTTyp):

    def __init__(self, ikind: str) -> None:
        ASTTyp.__init__(self, "int")
        if ikind in inttypes:
            self._ikind = ikind
        else:
            raise Exception(ikind + " is not a recognized integer type")

    @property
    def ikind(self) -> str:
        return self._ikind

    @property
    def is_integer(self) -> bool:
        return True

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_integer_typ(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTTyp":
        return transformer.transform_integer_typ(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_integer_typ(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_integer_typ(self)

    def __str__(self) -> str:
        return inttypes[self.ikind]

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ASTTypInt):
            return False
        return self.ikind == other.ikind

class ASTTypFloat(ASTTyp):

    def __init__(self, fkind: str) -> None:
        ASTTyp.__init__(self, "float")
        if fkind in floattypes:
            self._fkind = fkind
        else:
            raise Exception(fkind + " is not a recognized float type")

    @property
    def fkind(self) -> str:
        return self._fkind

    @property
    def is_float(self) -> bool:
        return True

    def accept(self, visitor: "ASTVisitor") -> None:
        return visitor.visit_float_typ(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTTyp":
        return transformer.transform_float_typ(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_float_typ(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_float_typ(self)

    def __str_(self) -> str:
        return floattypes[self.fkind]

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ASTTypFloat):
            return False
        return self.fkind == other.fkind


class ASTTypPtr(ASTTyp):

    def __init__(self, tgttyp: "ASTTyp") -> None:
        ASTTyp.__init__(self, "ptr")
        self._tgttyp = tgttyp

    @property
    def tgttyp(self) -> "ASTTyp":
        return self._tgttyp

    @property
    def is_pointer(self) -> bool:
        return True

    def accept(self, visitor: "ASTVisitor") -> None:
        return visitor.visit_pointer_typ(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTTyp":
        return transformer.transform_pointer_typ(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_pointer_typ(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_pointer_typ(self)

    def __str__(self) -> str:
        return str(self.tgttyp) + " *"

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ASTTypPtr):
            return False
        return self.tgttyp == other.tgttyp


class ASTTypArray(ASTTyp):

    def __init__(self, tgttyp: "ASTTyp", sizexpr: Optional["ASTExpr"]) -> None:
        ASTTyp.__init__(self, "array")
        self._tgttyp = tgttyp
        self._sizexpr = sizexpr

    @property
    def tgttyp(self) -> "ASTTyp":
        return self._tgttyp

    @property
    def size_expr(self) -> Optional["ASTExpr"]:
        return self._sizexpr

    @property
    def is_array(self) -> bool:
        return True

    def has_size_expr(self) -> bool:
        return self.size_expr is not None

    def has_constant_size(self) -> bool:
        return (self.size_expr is not None) and self.size_expr.is_integer_constant

    def size_value(self) -> int:
        if self.size_expr is not None:
            if self.size_expr.is_integer_constant:
                c = cast("ASTIntegerConstant", self.size_expr)
                return c.cvalue
        raise Exception("ASTTypArray does not have constant size: " + str(self))

    def accept(self, visitor: "ASTVisitor") -> None:
        return visitor.visit_array_typ(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTTyp":
        return transformer.transform_array_typ(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_array_typ(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_array_typ(self)

    def __str__(self) -> str:
        if self.size_expr is not None:
            return str(self.tgttyp) + "[" + str(self.size_expr) + "]"
        else:
            return str(self.tgttyp) + "[]"

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ASTTypArray):
            return False

        if self.tgttyp != other.tgttyp:
            return False

        if self.has_constant_size() and other.has_constant_size():
            return self.size_value() == other.size_value()
        else:
            # This becomes object equality, which we believe is fine.
            return self.size_expr == other.size_expr


class ASTTypFun(ASTTyp):

    def __init__(
            self,
            returntyp: "ASTTyp",
            argtypes: Optional["ASTFunArgs"],
            varargs: bool = False) -> None:
        ASTTyp.__init__(self, "funtype")
        self._returntyp = returntyp
        self._argtypes = argtypes
        self._varargs = varargs

    @property
    def returntyp(self) -> "ASTTyp":
        return self._returntyp

    @property
    def argtypes(self) -> Optional["ASTFunArgs"]:
        return self._argtypes

    @property
    def is_function(self) -> bool:
        return True

    @property
    def is_varargs(self) -> bool:
        return self._varargs

    def accept(self, visitor: "ASTVisitor") -> None:
        return visitor.visit_fun_typ(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTTyp":
        return transformer.transform_fun_typ(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_fun_typ(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_fun_typ(self)

    def __str__(self) -> str:
        return "(" + str(self.argtypes) + "):" + str(self.returntyp) + " "

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ASTTypFun):
            return False

        if self.returntyp != other.returntyp:
            return False

        if self.is_varargs != other.is_varargs:
            return False

        return self.argtypes == other.argtypes


class ASTFunArgs(ASTNode):

    def __init__(self, funargs: List["ASTFunArg"]) -> None:
        ASTNode.__init__(self, "funargs")
        self._funargs = funargs

    @property
    def funargs(self) -> List["ASTFunArg"]:
        return self._funargs

    def accept(self, visitor: "ASTVisitor") -> None:
        return visitor.visit_funargs(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTFunArgs":
        return transformer.transform_funargs(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_funargs(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_funargs(self)

    def __str__(self) -> str:
        return ", ".join(str(a) for a in self.funargs)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ASTFunArgs):
            return False

        if len(self.funargs) != len(other.funargs):
            return False

        # This assumes that ordering of the function arguments matters
        for my_arg, other_arg in zip(self.funargs, other.funargs):
            if my_arg != other_arg:
                return False

        return True


class ASTFunArg(ASTNode):

    def __init__(self, argname: str, argtyp: "ASTTyp") -> None:
        ASTNode.__init__(self, "funarg")
        self._argname = argname
        self._argtyp = argtyp

    @property
    def argname(self) -> str:
        return self._argname

    @property
    def argtyp(self) -> "ASTTyp":
        return self._argtyp

    def accept(self, visitor: "ASTVisitor") -> None:
        return visitor.visit_funarg(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTFunArg":
        return transformer.transform_funarg(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_funarg(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_funarg(self)

    def __str__(self) -> str:
        return str(self.argtyp) + " " + self.argname

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ASTFunArg):
            return False

        if self.argname != other.argname:
            return False

        return self.argtyp == other.argtyp


class ASTTypNamed(ASTTyp):

    def __init__(self, typname: str, typdef: "ASTTyp") -> None:
        ASTTyp.__init__(self, "typdef")
        self._typname = typname
        self._typdef = typdef

    @property
    def typname(self) -> str:
        return self._typname

    @property
    def typdef(self) -> "ASTTyp":
        return self._typdef

    @property
    def is_typedef(self) -> bool:
        return True

    def accept(self, visitor: "ASTVisitor") -> None:
        return visitor.visit_named_typ(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTTyp":
        return transformer.transform_named_typ(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_named_typ(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_named_typ(self)

    def __str__(self) -> str:
        return str(self.typdef) + " " + self.typname

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ASTTypNamed):
            return False

        if self.typname != other.typname:
            return False

        return self.typdef == other.typdef


class ASTTypBuiltinVAList(ASTTyp):

    def __init__(self) -> None:
        ASTTyp.__init__(self, "builtin-va-list")

    def accept(self, visitor: "ASTVisitor") -> None:
        return visitor.visit_builtin_va_list(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTTyp":
        return transformer.transform_builtin_va_list(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_builtin_va_list(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_builtin_va_list(self)

    def __str__(self) -> str:
        return "builtin-va-list"


class ASTFieldInfo(ASTNode):

    def __init__(
            self,
            fieldname: str,
            fieldtype: "ASTTyp",
            compkey: int,
            byteoffset: Optional[int] = None) -> None:
        ASTNode.__init__(self, "fieldinfo")
        self._fieldname = fieldname
        self._fieldtype = fieldtype
        self._compkey = compkey
        self._byteoffset = byteoffset

    @property
    def fieldname(self) -> str:
        return self._fieldname

    @property
    def fieldtype(self) -> "ASTTyp":
        return self._fieldtype

    @property
    def compkey(self) -> int:
        return self._compkey

    @property
    def byteoffset(self) -> Optional[int]:
        return self._byteoffset

    def has_byteoffset(self) -> bool:
        return self.byteoffset is not None

    def accept(self, visitor: "ASTVisitor") -> None:
        return visitor.visit_fieldinfo(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTFieldInfo":
        return transformer.transform_fieldinfo(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_fieldinfo(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_fieldinfo(self)

    def __str__(self) -> str:
        p_offset = str(self.byteoffset) + " " if self.byteoffset is not None else ""
        return p_offset + self.fieldname + ": " + str(self.fieldtype)


class ASTCompInfo(ASTNode):

    def __init__(
            self,
            compname: str,
            compkey: int,
            fieldinfos: List["ASTFieldInfo"],
            is_union: bool = False) -> None:
        ASTNode.__init__(self, "compinfo")
        self._compname = compname
        self._compkey = compkey
        self._fieldinfos = fieldinfos
        self._is_union = is_union

    @property
    def compname(self) -> str:
        return self._compname

    @property
    def compkey(self) -> int:
        return self._compkey

    @property
    def fieldinfos(self) -> List["ASTFieldInfo"]:
        return self._fieldinfos

    @property
    def is_union(self) -> bool:
        return self._is_union

    @property
    def is_compinfo(self) -> bool:
        return True

    def has_field_offsets(self) -> bool:
        return all(finfo.has_byteoffset() for finfo in self.fieldinfos)

    @property
    def field_offsets(self) -> Dict[int, str]:
        result: Dict[int, str] = {}
        if self.has_field_offsets():
            for finfo in self.fieldinfos:
                byteoffset = cast(int, finfo.byteoffset)
                result[byteoffset] = finfo.fieldname
            return result
        else:
            raise Exception(
                "No field offsets are specified for compinfo " + self.compname)

    def field_at_offset(self, offset: int) -> Tuple["ASTFieldInfo", int]:
        """Return the field at the max offset less than or equal to offset.

        If the field is not at offset, also return the remaining offset.
        """

        if offset < 0:
            raise Exception(
                "Negative offset in field_at_offset: " + str(offset))

        if not self.has_field_offsets():
            raise Exception(
                "No field offsets are specified for compinfo " + self.compname)

        prev: Optional[Tuple[int, str]] = None
        for (i, fname) in self.field_offsets.items():
            if i == offset:
                return (self.fieldinfo(fname), 0)
            elif i > offset:
                prev = cast(Tuple[int, str], prev)
                return (self.fieldinfo(prev[1]), offset - prev[0])
            else:
                prev = (i, fname)
        else:
            if prev is not None:
                prev = cast(Tuple[int, str], prev)
                return (self.fieldinfo(prev[1]), offset - prev[0])
            else:
                raise Exception(
                    "No field found at offset "
                    + str(offset)
                    + " in struct "
                    + self.compname)

    def fieldinfo(self, fname: str) -> "ASTFieldInfo":
        for finfo in self.fieldinfos:
            if finfo.fieldname == fname:
                return finfo
        else:
            raise Exception("No fieldinfo found with fieldname " + fname)

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_compinfo(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTCompInfo":
        return transformer.transform_compinfo(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_compinfo(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_compinfo(self)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append(self.compname + " (" + str(self.compkey) + ")")
        for finfo in self.fieldinfos:
            lines.append("  " + str(finfo))
        return "\n".join(lines)


class ASTTypComp(ASTTyp):

    def __init__(
            self,
            compname: str,
            compkey: int) -> None:
        ASTTyp.__init__(self, "comptyp")
        self._compname = compname
        self._compkey = compkey

    @property
    def compkey(self) -> int:
        return self._compkey

    @property
    def compname(self) -> str:
        return self._compname

    @property
    def is_compound(self) -> bool:
        return True

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_comp_typ(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTTyp":
        return transformer.transform_comp_typ(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_comp_typ(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_comp_typ(self)

    def __str__(self) -> str:
        return "struct " + self.compname

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ASTTypComp):
            return False

        if self.compkey != other.compkey:
            return False

        return self.compname == other.compname


class ASTEnumItem(ASTNode):

    def __init__(self, itemname: str, itemexpr: "ASTExpr") -> None:
        ASTNode.__init__(self, "enumitem")
        self._itemname = itemname
        self._itemexpr = itemexpr

    @property
    def itemname(self) -> str:
        return self._itemname

    @property
    def itemexpr(self) -> "ASTExpr":
        return self._itemexpr

    def accept(self, visitor: "ASTVisitor") -> None:
        return visitor.visit_enumitem(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTEnumItem":
        return transformer.transform_enumitem(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_enumitem(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_enumitem(self)

    def __str__(self) -> str:
        return self.itemname + ":" + str(self.itemexpr)


class ASTEnumInfo(ASTNode):

    def __init__(
            self,
            enumname: str,
            enumitems: List["ASTEnumItem"],
            enumkind: str) -> None:
        ASTNode.__init__(self, "enuminfo")
        self._enumname = enumname
        self._enumitems = enumitems
        self._enumkind = enumkind

    @property
    def enumname(self) -> str:
        return self._enumname

    @property
    def enumitems(self) -> List["ASTEnumItem"]:
        return self._enumitems

    @property
    def enumkind(self) -> str:
        return self._enumkind

    @property
    def is_enuminfo(self) -> bool:
        return True

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_enuminfo(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTEnumInfo":
        return transformer.transform_enuminfo(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_enuminfo(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_enuminfo(self)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append(self.enumname)
        for enumitem in self.enumitems:
            lines.append("  " + str(enumitem))
        return "\n".join(lines)


class ASTTypEnum(ASTTyp):

    def __init__(self, enumname: str, enumkind: str) -> None:
        ASTTyp.__init__(self, "enumtyp")
        self._enumname = enumname
        self._enumkind = enumkind

    @property
    def enumname(self) -> str:
        return self._enumname

    @property
    def enumkind(self) -> str:
        return self._enumkind

    @property
    def is_enum(self) -> bool:
        return True

    def accept(self, visitor: "ASTVisitor") -> None:
        visitor.visit_enum_typ(self)

    def transform(self, transformer: "ASTTransformer") -> "ASTTyp":
        return transformer.transform_enum_typ(self)

    def index(self, indexer: "ASTIndexer") -> int:
        return indexer.index_enum_typ(self)

    def ctype(self, ctyper: "ASTCTyper") -> Optional["ASTTyp"]:
        return ctyper.ctype_enum_typ(self)

    def __str__(self) -> str:
        return "enum " + self.enumname

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ASTTypEnum):
            return False

        if self.enumkind != other.enumkind:
            return False

        return self.enumname == other.enumname
