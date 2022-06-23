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
"""Pretty printer for code represented as an abstract syntax tree."""

from typing import cast, Dict, List, Optional, Set, TYPE_CHECKING

import chb.ast.ASTNode as AST
from chb.ast.ASTVisitor import ASTVisitor


if TYPE_CHECKING:
    from chb.ast.ASTSymbolTable import ASTGlobalSymbolTable, ASTLocalSymbolTable


operators = AST.operators


class ASTCCode:

    def __init__(self) -> None:
        self._outputlines: List[str] = []

    @property
    def outputlines(self) -> List[str]:
        return self._outputlines

    def newline(self, indent: int = 0) -> None:
        self._outputlines.append(" " * indent)

    def write(self, s: str) -> None:
        self._outputlines[-1] += s

    def __str__(self) -> str:
        return "\n".join(self.outputlines)


class ASTCPrettyPrinter(ASTVisitor):

    def __init__(
            self,
            localsymboltable: "ASTLocalSymbolTable",
            indentation: int = 2,
            livecode: List[int] = [],
            livesymbols: Set[str] = set([]),
            annotations: Dict[int, List[str]] = {},
            livevars_on_exit: Dict[int, Set[str]] = {}) -> None:
        self._indentation = indentation    # indentation amount
        self._indent = 0                   # current indentation
        self._localsymboltable = localsymboltable
        self._globalsymboltable = localsymboltable.globaltable
        self._livecode = livecode
        self._livesymbols = livesymbols
        self._annotations = annotations
        self._livevars_on_exit = livevars_on_exit
        self._ccode = ASTCCode()

    @property
    def indentation(self) -> int:
        return self._indentation

    @property
    def localsymboltable(self) -> "ASTLocalSymbolTable":
        return self._localsymboltable

    @property
    def globalsymboltable(self) -> "ASTGlobalSymbolTable":
        return self._globalsymboltable

    @property
    def signature(self) -> Optional[AST.ASTVarInfo]:
        if self.localsymboltable.has_function_prototype():
            return self.localsymboltable.function_prototype
        else:
            return None

    def has_signature(self) -> bool:
        return self.signature is not None

    @property
    def indent(self) -> int:
        return self._indent

    @property
    def livecode(self) -> List[int]:
        return self._livecode

    @property
    def livesymbols(self) -> Set[str]:
        return self._livesymbols

    @property
    def annotations(self) -> Dict[int, List[str]]:
        return self._annotations

    @property
    def livevars_on_exit(self) -> Dict[int, Set[str]]:
        return self._livevars_on_exit

    @property
    def ccode(self) -> ASTCCode:
        return self._ccode

    def increase_indent(self) -> None:
        self._indent += self.indentation

    def decrease_indent(self) -> None:
        self._indent -= self.indentation

    def is_live(self, id: int) -> bool:
        return len(self.livecode) == 0 or id in self.livecode

    def is_returnval_live(self, id: int, name: str) -> bool:
        return (
            id in self.livevars_on_exit and name in self.livevars_on_exit[id])

    def annotation(self, id: int, sep: str = ", ") -> str:
        if id in self.annotations:
            return sep.join(self.annotations[id])
        else:
            return ""

    def write_local_declarations(self) -> None:
        for vinfo in self.localsymboltable.symbols:
            if (
                    vinfo.vname in self.livesymbols
                    and not self.localsymboltable.is_formal(vinfo.vname)):
                self.ccode.newline()
                if vinfo.vtype is not None:
                    vinfo.vtype.accept(self)
                    self.ccode.write(" " + vinfo.vname + ";")
                else:
                    self.ccode.write("? " + vinfo.vname)

    def write_signature(self) -> None:
        if self.signature is not None:
            vtype = self.signature.vtype
            if vtype is not None and vtype.is_function:
                ftype = cast(AST.ASTTypFun, vtype)
                ftype.returntyp.accept(self)
                self.ccode.write(" ")
                self.ccode.write(self.signature.vname)
                self.ccode.write("(")
                if ftype.argtypes is not None:
                    ftype.argtypes.accept(self)
                self.ccode.write(")")
                return None
            else:
                self.ccode.write("? ")
                self.ccode.write(self.signature.vname)
                self.ccode.write("(?)")

    def to_c(self, stmt: AST.ASTStmt, sp: int = 0) -> str:
        if self.signature is not None:
            self.ccode.newline()
            self.write_signature()
            self.ccode.write("{")
            self.increase_indent()
            self.ccode.newline()
            self.write_local_declarations()
            self.ccode.newline()
            self.stmt_to_c(stmt)
            self.decrease_indent()
            self.ccode.newline()
            self.ccode.write("}")
        else:
            self.ccode.newline()
            self.write_local_declarations()
            self.ccode.newline()
            self.stmt_to_c(stmt)
            self.ccode.newline()
        return str(self.ccode)

    def stmt_to_c(self, stmt: AST.ASTStmt) -> None:
        if stmt.is_ast_return:
            self.visit_return_stmt(cast(AST.ASTReturn, stmt))
        elif stmt.is_ast_block:
            self.visit_block_stmt(cast(AST.ASTBlock, stmt))
        elif stmt.is_ast_instruction_sequence:
            self.visit_instruction_sequence_stmt(cast(AST.ASTInstrSequence, stmt))
        elif stmt.is_ast_branch:
            self.visit_branch_stmt(cast(AST.ASTBranch, stmt))
        else:
            raise Exception("Statement type not recognized: " + stmt.tag)

    def expr_to_c(self, expr: AST.ASTExpr) -> str:
        self.ccode.newline()
        expr.accept(self)
        return str(self.ccode)

    def visit_return_stmt(self, stmt: AST.ASTReturn) -> None:
        self.ccode.newline(indent=self.indent)
        if stmt.has_return_value():
            self.ccode.write("return ")
            stmt.expr.accept(self)
            self.ccode.write(";")
        else:
            self.ccode.write("return;")

    def visit_block_stmt(self, stmt: AST.ASTBlock) -> None:
        for s in stmt.stmts:
            if self.is_live(s.assembly_xref):
                s.accept(self)

    def visit_instruction_sequence_stmt(self, stmt: AST.ASTInstrSequence) -> None:
        for i in stmt.instructions:
            if self.is_live(i.assembly_xref):
                i.accept(self)

    def visit_branch_stmt(self, stmt: AST.ASTBranch) -> None:

        def empty_else_branch(s: AST.ASTStmt) -> bool:
            if s.is_ast_block:
                s = cast(AST.ASTBlock, s)
                if len(s.stmts) == 0:
                    return True
                elif len(s.stmts) == 1:
                    s1 = s.stmts[0]
                    if s1.is_ast_instruction_sequence:
                        s1 = cast(AST.ASTInstrSequence, s1)
                        return (len(s1.instructions) == 0)
            elif s.is_ast_instruction_sequence:
                s = cast(AST.ASTInstrSequence, s)
                return (len(s.instructions) == 0)
            return False

        self.ccode.newline(indent=self.indent)
        self.ccode.write("if (")
        stmt.condition.accept(self)
        self.ccode.write(") {")
        self.increase_indent()
        stmt.ifstmt.accept(self)
        self.decrease_indent()
        if empty_else_branch(stmt.elsestmt):
            pass
        else:
            self.ccode.newline(indent=self.indent)
            self.ccode.write("} else {")
            self.increase_indent()
            stmt.elsestmt.accept(self)
            self.decrease_indent()
        self.ccode.newline(indent=self.indent)
        self.ccode.write("}")

    def visit_assign_instr(self, instr: AST.ASTAssign) -> None:
        self.ccode.newline(indent=self.indent)
        instr.lhs.accept(self)
        self.ccode.write(" = ")
        instr.rhs.accept(self)
        self.ccode.write(";")
        if len(self.annotation(instr.assembly_xref)) > 0:
            self.ccode.write(" // " + self.annotation(instr.assembly_xref))

    def visit_call_instr(self, instr: AST.ASTCall) -> None:
        self.ccode.newline(indent=self.indent)
        if instr.lhs is not None:
            lhslive = self.is_returnval_live(instr.assembly_xref, str(instr.lhs))
            if lhslive:
                instr.lhs.accept(self)
                self.ccode.write(" = ")
        instr.tgt.accept(self)
        self.ccode.write("(")
        if len(instr.arguments) > 0:
            for a in instr.arguments[:-1]:
                a.accept(self)
                self.ccode.write(", ")
            instr.arguments[-1].accept(self)
        self.ccode.write(");")
        if len(self.annotation(instr.assembly_xref)) > 0:
            self.ccode.write(" // " + self.annotation(instr.assembly_xref))

    def visit_lval(self, lval: AST.ASTLval) -> None:
        if lval.lhost.is_memref:
            memexp = cast(AST.ASTMemRef, lval.lhost).memexp
            if lval.offset.is_field_offset:
                fieldname = cast(AST.ASTFieldOffset, lval.offset).fieldname
                suboffset = cast(AST.ASTFieldOffset, lval.offset).offset
                memexp.accept(self)
                self.ccode.write("->" + fieldname)
                suboffset.accept(self)
            elif lval.offset.is_index_offset:
                indexoffset = cast(AST.ASTIndexOffset, lval.offset)
                memexp.accept(self)
                self.ccode.write(" + ")
                indexoffset.accept(self)
            else:
                lval.lhost.accept(self)
                lval.offset.accept(self)
        else:
            lval.lhost.accept(self)
            lval.offset.accept(self)

    def visit_varinfo(self, vinfo: AST.ASTVarInfo) -> None:
        if vinfo.vtype is not None:
            vinfo.vtype.accept(self)
        else:
            self.ccode.write("?")
        self.ccode.write(" ")
        self.ccode.write(vinfo.vname)

    def visit_variable(self, var: AST.ASTVariable) -> None:
        self.ccode.write(var.vname)

    def visit_memref(self, memref: AST.ASTMemRef) -> None:
        self.ccode.write("(*(")
        memref.memexp.accept(self)
        self.ccode.write("))")

    def visit_no_offset(self, offset: AST.ASTNoOffset) -> None:
        pass

    def visit_field_offset(self, offset: AST.ASTFieldOffset) -> None:
        self.ccode.write("." + offset.fieldname)
        offset.offset.accept(self)

    def visit_index_offset(self, offset: AST.ASTIndexOffset) -> None:
        self.ccode.write("[")
        offset.index_expr.accept(self)
        self.ccode.write("]")
        offset.offset.accept(self)

    def visit_integer_constant(self, c: AST.ASTIntegerConstant) -> None:
        if c.cvalue > 10000:
            self.ccode.write(hex(c.cvalue))
        else:
            self.ccode.write(str(c.cvalue))

    def visit_global_address(self, g: AST.ASTGlobalAddressConstant) -> None:
        g.address_expr.accept(self)

    def visit_string_constant(self, s: AST.ASTStringConstant) -> None:
        self.ccode.write('"' + s.cstr + '"')

    def visit_lval_expression(self, lvalexpr: AST.ASTLvalExpr) -> None:
        lvalexpr.lval.accept(self)

    def visit_sizeof_expression(self, expr: AST.ASTSizeOfExpr) -> None:
        self.ccode.write("sizeof(")
        expr.tgt_type.accept(self)
        self.ccode.write(")")

    def visit_cast_expression(self, castexpr: AST.ASTCastExpr) -> None:
        self.ccode.write("(")
        castexpr.cast_tgt_type.accept(self)
        self.ccode.write(")")
        castexpr.cast_expr.accept(self)

    def visit_unary_expression(self, unop: AST.ASTUnaryOp) -> None:
        self.ccode.write(operators[unop.op])
        unop.exp1.accept(self)

    def visit_binary_expression(self, binop: AST.ASTBinaryOp) -> None:
        self.ccode.write("(")
        binop.exp1.accept(self)
        self.ccode.write(operators[binop.op])
        binop.exp2.accept(self)
        self.ccode.write(")")

    def visit_question_expression(self, qexpr: AST.ASTQuestion) -> None:
        self.ccode.write("(")
        qexpr.exp1.accept(self)
        self.ccode.write(" ? ")
        qexpr.exp2.accept(self)
        self.ccode.write(" : ")
        qexpr.exp3.accept(self)
        self.ccode.write(")")

    def visit_address_of_expression(self, addressof: AST.ASTAddressOf) -> None:
        self.ccode.write("&")
        addressof.lval.accept(self)

    def visit_void_typ(self, t: AST.ASTTypVoid) -> None:
        self.ccode.write("void")

    def visit_integer_typ(self, t: AST.ASTTypInt) -> None:
        self.ccode.write(str(t))

    def visit_float_typ(self, t: AST.ASTTypFloat) -> None:
        self.ccode.write(str(t))

    def visit_pointer_typ(self, t: AST.ASTTypPtr) -> None:
        t.tgttyp.accept(self)
        self.ccode.write(" *")

    def visit_array_typ(self, t: AST.ASTTypArray) -> None:
        t.tgttyp.accept(self)
        self.ccode.write("[")
        if t.size_expr is not None:
            t.size_expr.accept(self)
        self.ccode.write("]")

    def visit_fun_typ(self, t: AST.ASTTypFun) -> None:
        """Emits a function type without name."""

        t.returntyp.accept(self)
        self.ccode.write(" (")
        if t.argtypes is not None:
            t.argtypes.accept(self)
        self.ccode.write(")")

    def visit_funargs(self, funargs: AST.ASTFunArgs) -> None:
        args = funargs.funargs
        if len(args) == 0:
            pass
        else:
            for arg in args[:-1]:
                arg.accept(self)
                self.ccode.write(", ")
            args[-1].accept(self)

    def visit_funarg(self, funarg: AST.ASTFunArg) -> None:
        funarg.argtyp.accept(self)
        self.ccode.write(" ")
        self.ccode.write(funarg.argname)

    def visit_named_typ(self, t: AST.ASTTypNamed) -> None:
        self.ccode.write("typedef ")
        t.typdef.accept(self)
        self.ccode.write(" ")
        self.ccode.write(t.typname)

    def visit_builtin_va_list(sef, t: AST.ASTTypBuiltinVAList) -> None:
        pass

    def visit_comp_typ(self, t: AST.ASTTypComp) -> None:
        self.ccode.write("struct " + t.compname)

    def visit_compinfo(self, cinfo: AST.ASTCompInfo) -> None:
        self.ccode.write("compinfo")

    def visit_fieldinfo(self, finfo: AST.ASTFieldInfo) -> None:
        pass
