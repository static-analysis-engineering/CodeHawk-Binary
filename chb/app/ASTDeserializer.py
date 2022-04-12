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
"""Simplified version of AST to check serialization."""

from typing import Any, cast, Dict, List, NewType, Optional, Tuple, Union

ASTSpanRecord = NewType(
    "ASTSpanRecord", Dict[str, Union[int, List[Dict[str, Union[str, int]]]]])

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
    "neq": " != ",
    "plus": " + "
    }

nodecache: Dict[int, "ASTNode"] = {}


duplicate_nodes: Dict[int, List["ASTNode"]] = {}


def add_to_node_cache(id: int, node: "ASTNode") -> None:
    if id in nodecache:
        duplicate_nodes.setdefault(id, [nodecache[id]])
        duplicate_nodes[id].append(node)
    nodecache[id] = node


def duplicates_to_string() -> str:
    lines: List[str] = []
    for (id, nodes) in sorted(duplicate_nodes.items()):
        lines.append("\n" + str(id))
        for n in nodes:
            lines.append(
                "  " + n.tag + " [" + ", ".join(str(a) for a in n.args) + "]")
    return "\n".join(lines)


class ASTNode:

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        self._id = id
        self._tag = tag
        self._args = args

    @property
    def id(self) -> int:
        return self._id

    @property
    def tag(self) -> str:
        return self._tag

    @property
    def args(self) -> List[int]:
        return self._args

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        return (
            (" " * sp)
            + str(self.id)
            + ": "
            + self.tag
            + "[" + ", ".join(str(a) for a in self.args) + "]")

    def __str__(self) -> str:
        return self.to_c_like()


class ASTStmt(ASTNode):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTNode.__init__(self, id, tag, args)


class ASTReturn(ASTStmt):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTStmt.__init__(self, id, tag, args)


class ASTBlock(ASTStmt):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTStmt.__init__(self, id, tag, args)

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        lines: List[str] = []
        for a in self.args:
            lines.append(nodecache[a].to_c_like(sp, spanmap=spanmap))
        return "\n".join(lines)


class ASTInstrSequence(ASTStmt):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTStmt.__init__(self, id, tag, args)

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        lines: List[str] = []
        for a in self.args:
            lines.append(nodecache[a].to_c_like(sp, spanmap=spanmap))
        return "\n".join(lines)


class ASTBranch(ASTStmt):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTStmt.__init__(self, id, tag, args)

    @property
    def condition(self) -> "ASTExpr":
        return cast("ASTExpr", nodecache[self.args[0]])

    @property
    def ifstmt(self) -> "ASTStmt":
        return cast("ASTStmt", nodecache[self.args[1]])

    @property
    def elsestmt(self) -> "ASTStmt":
        return cast("ASTStmt", nodecache[self.args[2]])

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        lines: List[str] = []
        indent = " " * sp
        lines.append(
            indent
            + "if ("
            + self.condition.to_c_like()
            + "){")
        lines.append(self.ifstmt.to_c_like(sp + c_indent, spanmap=spanmap))
        lines.append(indent + "} else {")
        lines.append(self.elsestmt.to_c_like(sp + c_indent, spanmap=spanmap))
        lines.append(indent + "}")
        return "\n".join(lines)                     
    
    
class ASTInstruction(ASTNode):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTNode.__init__(self, id, tag, args)
    

class ASTAssign(ASTInstruction):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTInstruction.__init__(self, id, tag, args)

    @property
    def lhs(self) -> "ASTLval":
        return cast("ASTLval", nodecache[self.args[0]])

    @property
    def rhs(self) -> "ASTExpr":
        return cast("ASTExpr", nodecache[self.args[1]])
    
    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        span = spanmap[self.id] if self.id in spanmap else "no span found"
        return (
            (" " * sp)
            + self.lhs.to_c_like()
            + " = "
            + self.rhs.to_c_like()
            + ";"
            + " // " + str(self.id)
            + " ("
            + span
            + ")")
        

class ASTCall(ASTInstruction):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTInstruction.__init__(self, id, tag, args)

    @property
    def lhs(self) -> Optional["ASTLval"]:
        if self.args[0] == -1:
            return None
        else:
            return cast("ASTLval", nodecache[self.args[0]])

    @property
    def tgt(self) -> "ASTExpr":
        return cast("ASTExpr", nodecache[self.args[1]])

    @property
    def arguments(self) -> List["ASTExpr"]:
        return [cast("ASTExpr", nodecache[a]) for a in self.args[2:]]

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        indent = " " * sp
        calltgt = (
            self.tgt.to_c_like()
            + "("
            + ", ".join(str(a.to_c_like()) for a in self.arguments)
            + "); // "
            + str(self.id)
            + " ("
            + spanmap[self.id]
            + ")")
        if self.lhs:
            return indent + self.lhs.to_c_like() + " = " + calltgt
        else:
            return indent + calltgt


class ASTLval(ASTNode):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTNode.__init__(self, id, tag, args)

    @property
    def lhost(self) -> "ASTLHost":
        return cast("ASTLHost", nodecache[self.args[0]])

    @property
    def is_memref(self) -> bool:
        return self.lhost.is_memref

    @property
    def offset(self) -> "ASTOffset":
        if self.args[1] == -1:
            return ASTNoOffset(-1, "no-offset", [])
        else:
            return cast("ASTOffset", nodecache[self.args[1]])

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        if self.lhost.is_memref:
            memref = cast("ASTMemRef", self.lhost)
            memexp = memref.memexp
            if self.offset.is_field_offset:
                fieldoffset = cast("ASTFieldOffset", self.offset)
                fieldname = fieldoffset.fieldname
                return memexp.to_c_like() + "->" + str(self.offset)[1:]
            elif self.offset.is_index_offset:
                indexoffset = cast("ASTIndexOffset", self.offset)
                return (
                    memexp.to_c_like()
                    + " + "
                    + indexoffset.index_expr.to_c_like())
            else:
                return self.lhost.to_c_like() + self.offset.to_c_like()
        else:
            return self.lhost.to_c_like() + self.offset.to_c_like()            


class ASTLHost(ASTNode):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTNode.__init__(self, id, tag, args)

    @property
    def is_memref(self) -> bool:
        return False

    @property
    def is_variable(self) -> bool:
        return False


class ASTVarInfo(ASTNode):

    def __init__(
            self,
            id: int,
            tag: str,
            args: List[int],
            vname: str,
            altname: Optional[str]) -> None:
        ASTNode.__init__(self, id, tag, args)
        self._vname = vname
        self._altname = altname

    @property
    def vname(self) -> str:
        return self._vname

    @property
    def altname(self) -> Optional[str]:
        return self._altname

    @property
    def displayname(self) -> str:
        if self.altname:
            return self.altname
        else:
            return self.vname

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        return self.displayname


class ASTVariable(ASTLHost):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTLHost.__init__(self, id, tag, args)

    @property
    def is_variable(self) -> bool:
        return True

    @property
    def varinfo(self) -> "ASTVarInfo":
        return cast("ASTVarInfo", nodecache[self.args[0]])

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        return self.varinfo.displayname
        


class ASTMemRef(ASTLHost):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTLHost.__init__(self, id, tag, args)

    @property
    def is_memref(self) -> bool:
        return True

    @property
    def memexp(self) -> "ASTExpr":
        return cast("ASTExpr", nodecache[self.args[0]])

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        return "(*(" + self.memexp.to_c_like() + ")"


class ASTOffset(ASTNode):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTNode.__init__(self, id, tag, args)

    @property
    def is_field_offset(self) -> bool:
        return False

    @property
    def is_index_offset(self) -> bool:
        return False


class ASTNoOffset(ASTOffset):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTOffset.__init__(self, id, tag, args)

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        return ""
    

no_offset = ASTNoOffset(-1, "no-offset", [])


class ASTFieldOffset(ASTOffset):

    def __init__(self, id: int, tag: str, args: List[int], fname: str) -> None:
        ASTOffset.__init__(self, id, tag, args)
        self._fieldname = fname

    @property
    def is_field_offset(self) -> bool:
        return True

    @property
    def fieldname(self) -> str:
        return self._fieldname

    @property
    def offset(self) -> "ASTOffset":
        if self.args[0] == -1:
            return no_offset
        else:
            return cast("ASTOffset", nodecache[self.args[0]])

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        return "." + self.fieldname + self.offset.to_c_like()


class ASTIndexOffset(ASTOffset):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTOffset.__init__(self, id, tag, args)

    @property
    def is_index_offset(self) -> bool:
        return True

    @property
    def index_expr(self) -> "ASTExpr":
        return cast("ASTExpr", nodecache[self.args[0]])

    @property
    def offset(self) -> "ASTOffset":
        if self.args[1] == -1:
            return no_offset
        else:
            return cast("ASTOffset", nodecache[self.args[1]])

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        return "[" + self.index_expr.to_c_like() + "]"


class ASTExpr(ASTNode):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTNode.__init__(self, id, tag, args)


class ASTConstant(ASTExpr):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTExpr.__init__(self, id, tag, args)

    
class ASTIntegerConstant(ASTConstant):

    def __init__(
            self,
            id: int,
            tag: str,
            args: List[int],
            cvalue: int,
            macroname: Optional[str]) -> None:
        ASTConstant.__init__(self, id, tag, args)
        self._cvalue = cvalue
        self._macroname = macroname

    @property
    def cvalue(self) -> int:
        return self._cvalue

    @property
    def macroname(self) -> Optional[str]:
        return self._macroname

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        if self.macroname:
            return self.macroname
        elif self.cvalue > 1000:
            return hex(self.cvalue)
        else:
            return str(self.cvalue)


class ASTStringConstant(ASTConstant):

    def __init__(
            self,
            id: int,
            tag: str,
            args: List[int],
            cstr: str,
            va: str) -> None:
        ASTConstant.__init__(self, id, tag, args)
        self._cstr = cstr
        self._va = va

    @property
    def cstr(self) -> str:
        return self._cstr

    @property
    def string_address(self) -> str:
        return self._va

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        return '"' + self.cstr + '"'


class ASTLvalExpr(ASTExpr):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTExpr.__init__(self, id, tag, args)

    @property
    def lval(self) -> "ASTLval":
        return cast("ASTLval", nodecache[self.args[0]])

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        return self.lval.to_c_like(sp)


class ASTSubstitutedExpr(ASTLvalExpr):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTLvalExpr.__init__(self, id, tag, args)

    @property
    def expr(self) -> "ASTExpr":
        return cast("ASTExpr", nodecache[self.args[1]])

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        return self.expr.to_c_like(sp)


class ASTCastE(ASTExpr):

    def __init__(self, id: int, tag: str, args: List[int], tgttype: str) -> None:
        ASTExpr.__init__(self, id, tag, args)
        self._tgttype = tgttype

    @property
    def tgttype(self) -> str:
        return self._tgttype

    @property
    def expr(self) -> "ASTExpr":
        return cast("ASTExpr", nodecache[self.args[0]])

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        return "(" + self.tgttype + ")" + self.expr.to_c_like()
    
    
class ASTUnaryOp(ASTExpr):

    def __init__(self, id: int, tag: str, args: List[int], op: str) -> None:
        ASTExpr.__init__(self, id, tag, args)
        self._op = op

    @property
    def op(self) -> str:
        return self._op

    @property
    def expr(self) -> "ASTExpr":
        return cast("ASTExpr", nodecache[self.args[0]])

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        return operators[self.op] + self.expr.to_c_like(sp)
    

class ASTBinaryOp(ASTExpr):

    def __init__(self, id: int, tag: str, args: List[int], op: str) -> None:
        ASTExpr.__init__(self, id, tag, args)
        self._op = op

    @property
    def op(self) -> str:
        return self._op

    @property
    def exp1(self) -> "ASTExpr":
        return cast("ASTExpr", nodecache[self.args[0]])

    @property
    def exp2(self) -> "ASTExpr":
        return cast("ASTExpr", nodecache[self.args[1]])

    def to_c_like(self, sp: int = 0, spanmap: Dict[int, str] = {}) -> str:
        return (
            "("
            + self.exp1.to_c_like()
            + operators[self.op]
            + self.exp2.to_c_like()
            + ")")


class ASTQuestion(ASTExpr):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTExpr.__init__(self, id, tag, args)


class ASTAddressOf(ASTExpr):

    def __init__(self, id: int, tag: str, args: List[int]) -> None:
        ASTExpr.__init__(self, id, tag, args)
    
    
    
class AbstractSyntaxTree:

    def __init__(
            self,
            nodes: List[Dict[str, Any]],
            startnode: int,
            available_expressions: Dict[str, List[Tuple[int, str, str]]],
            spans: List["ASTSpanRecord"]) -> None:
        self._nodes = nodes
        self._startnode = startnode
        self._available_expressions = available_expressions
        self._spans = spans
        self._spanmap: Dict[int, str] = {}
        self._initialize()

    @property
    def nodes(self) -> List[Dict[str, Any]]:
        return self._nodes

    @property
    def available_expressions(self) -> Dict[str, List[Tuple[int, str, str]]]:
        return self._available_expressions

    @property
    def startnode(self) -> int:
        return self._startnode

    @property
    def spans(self) -> List["ASTSpanRecord"]:
        return self._spans

    @property
    def spanmap(self) -> Dict[int, str]:
        if len(self._spanmap) == 0:
            for spanrec in self.spans:
                spanid = cast(int, spanrec["id"])
                spans_at_id = cast(List[Dict[str, Any]], spanrec["spans"])
                self._spanmap[spanid] = spans_at_id[0]["base_va"]
        return self._spanmap                                           

    def _initialize(self) -> None:
        for n in self.nodes:
            id: int = n["id"]
            tag: str = n["tag"]
            args: List[int] = n["args"] if "args" in n else []
            node: ASTNode = ASTNode(-1, "?", [])
            if tag == "return":
                node = ASTReturn(id, tag, args)
            elif tag == "block":
                node = ASTBlock(id, tag, args)
            elif tag == "instrs":
                node = ASTInstrSequence(id, tag, args)
            elif tag == "if":
                node = ASTBranch(id, tag, args)
            elif tag == "assign":
                node = ASTAssign(id, tag, args)
            elif tag == "call":
                node = ASTCall(id, tag, args)
            elif tag == "lval":
                node = ASTLval(id, tag, args)
            elif tag == "varinfo":
                vname: str = n["vname"]
                altname: Optional[str] = n["altname"] if "altname" in n else None
                node = ASTVarInfo(id, tag, args, vname, altname)
            elif tag == "var":
                node = ASTVariable(id, tag, args)
            elif tag == "memref":
                node = ASTMemRef(id, tag, args)
            elif tag == "no-offset":
                node = ASTNoOffset(id, tag, args)
            elif tag == "field-offset":
                fname: str = n["fname"]
                node = ASTFieldOffset(id, tag, args, fname)
            elif tag == "index-offset":
                node = ASTIndexOffset(id, tag, args)
            elif tag == "integer-constant":
                cvalue: int = int(n["value"])
                name: Optional[str] = n["macroname"] if "macroname" in n else None
                node = ASTIntegerConstant(id, tag, args, cvalue, name)
            elif tag == "string-constant":
                cstr: str = n["cstr"]
                va: str = n["va"]
                node = ASTStringConstant(id, tag, args, cstr, va)
            elif tag == "lval-expr":
                node = ASTLvalExpr(id, tag, args)
            elif tag == "substituted-expr":
                node = ASTSubstitutedExpr(id, tag, args)
            elif tag == "cast-expr":
                tgttype: str = n["type"]
                node = ASTCastE(id, tag, args, tgttype)
            elif tag == "unary-op":
                unop: str = n["op"]
                node = ASTUnaryOp(id, tag, args, unop)
            elif tag == "binary-op":
                binop: str = n["op"]
                node = ASTBinaryOp(id, tag, args, binop)
            elif tag == "question":
                node = ASTQuestion(id, tag, args)
            elif tag == "address-of":
                node = ASTAddressOf(id, tag, args)
            else:
                node = ASTNode(id, tag, args)
            add_to_node_cache(id, node)

    def to_c_like(self):
        return nodecache[self.startnode].to_c_like(spanmap = self.spanmap)

    def var_available_expressions(self, names: List[str]) -> str:
        lines: List[str] = []
        for (addr, xlist) in sorted(self.available_expressions.items()):
            lines.append(addr)
            for (id, vname, vexpr) in xlist:
                if vname in names:
                    lines.append("  " + vname + ": " + vexpr + " (" + str(id) + ")")
        return "\n".join(lines)

    def __str__(self) -> str:
        lines: List[str] = []
        for (n, node) in sorted(nodecache.items()):
            lines.append(str(node))
        return "\n".join(lines)
            
