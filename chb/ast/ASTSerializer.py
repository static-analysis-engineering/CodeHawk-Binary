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
"""AST serialization to json format."""

from typing import Any, cast, Dict, List, Tuple

import chb.ast.ASTNode as AST


def get_key(tags: List[str], args: List[int]) -> Tuple[str, str]:
    return (",".join(tags), ",".join(str(i) for i in args))


class ASTNodeDictionary:

    def __init__(self) -> None:
        self.keytable: Dict[Tuple[str, str], int] = {}  # key -> index
        self.indextable: Dict[int, Dict[str, Any]] = {}  # index -> record
        self.next = 1

    def add(self, key: Tuple[str, str], node: Dict[str, Any]) -> int:
        if key in self.keytable:
            return self.keytable[key]
        else:
            index = self.next
            self.keytable[key] = index
            self.indextable[index] = node
            self.next += 1
            return index

    def records(self) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for (id, record) in sorted(self.indextable.items()):
            record["id"] = id
            result.append(record)
        return result
        

class ASTSerializer:

    def __init__(self) -> None:
        self._table: ASTNodeDictionary = ASTNodeDictionary()

    @property
    def table(self) -> ASTNodeDictionary:
        return self._table

    def records(self) -> List[Dict[str, Any]]:
        return self.table.records()

    def add(self, tags: List[str], args: List[int], node: Dict[str, Any]) -> int:
        node["args"] = args
        return self.table.add(get_key(tags, args), node)

    def index_stmt(self, stmt: AST.ASTStmt) -> int:
        tags: List[str] = [stmt.tag]
        args: List[int] = [stmt.stmtid]
        node: Dict[str, Any] = {"tag": stmt.tag}

        if stmt.tag == "return":
            stmt = cast(AST.ASTReturn, stmt)
            if stmt.has_return_value():
                args.append(self.index_expr(stmt.expr))

        elif stmt.tag == "block":
            stmt = cast(AST.ASTBlock, stmt)
            args.extend([self.index_stmt(s) for s in stmt.stmts])

        elif stmt.tag == "if":
            stmt = cast(AST.ASTBranch, stmt)
            tags.append(str(stmt.relative_offset))
            args.extend([
                self.index_expr(stmt.condition),
                self.index_stmt(stmt.ifstmt),
                self.index_stmt(stmt.elsestmt)])
            node["pc-offset"] = stmt.relative_offset

        elif stmt.tag == "instrs":
            stmt = cast(AST.ASTInstrSequence, stmt)
            args.extend([self.index_instruction(i) for i in stmt.instructions])

        else:
            raise Exception("Unexpected stmt tag: " + stmt.tag)

        return self.add(tags, args, node)

    def index_instruction(self, instr: AST.ASTInstruction) -> int:
        tags: List[str] = [instr.tag]
        args: List[int] = [instr.instrid]
        node: Dict[str, Any] = {"tag": instr.tag}

        if instr.tag == "assign":
            instr = cast(AST.ASTAssign, instr)
            args.extend([
                self.index_lval(instr.lhs), self.index_expr(instr.rhs)])

        elif instr.tag == "call":
            instr = cast(AST.ASTCall, instr)
            args.append(self.index_lval(instr.lhs))
            args.append(self.index_expr(instr.tgt))
            args.extend([self.index_expr(a) for a in instr.arguments])

        else:
            raise Exception("Unexpected instruction tag: " + instr.tag)

        return self.add(tags, args, node)

    def index_lval(self, lval: AST.ASTLval) -> int:
        tags: List[str] = [lval.tag]
        args: List[int] = [
            self.index_lhost(lval.lhost), self.index_offset(lval.offset)]
        node: Dict[str, Any] = {"tag": "lval"}
        return self.add(tags, args, node)

    def index_lhost(self, lhost: AST.ASTLHost) -> int:
        tags: List[str] = [lhost.tag]
        args: List[int] = []
        node: Dict[str, Any] = {"tag": lhost.tag}

        if lhost.tag == "var":
            lhost = cast(AST.ASTVariable, lhost)
            tags.append(lhost.vname)
            node["name"] = lhost.vname

        elif lhost.tag == "memref":
            lhost = cast(AST.ASTMemRef, lhost)
            args.append(self.index_expr(lhost.memexp))

        else:
            raise Exception("Unexpected lhost tag: " + lhost.tag)

        return self.add(tags, args, node)

    def index_offset(self, offset: AST.ASTOffset) -> int:
        tags: List[str] = [offset.tag]
        args: List[int] = []
        node: Dict[str, Any] = {"tag": offset.tag}

        if offset.tag == "no-offset":
            pass

        elif offset.tag == "field-offset":
            offset = cast(AST.ASTFieldOffset, offset)
            tags.append(offset.fieldname)
            args.append(self.index_offset(offset.offset))
            node["fname"] = offset.fieldname

        elif offset.tag == "index-offset":
            offset = cast(AST.ASTIndexOffset, offset)
            args.extend([
                self.index_expr(offset.index),
                self.index_offset(offset.offset)])

        else:
            raise Exception("Unexpected offset tag: " + offset.tag)

        return self.add(tags, args, node)

    def index_expr(self, expr: AST.ASTExpr) -> int:
        tags: List[str] = [expr.tag]
        args: List[int] = []
        node: Dict[str, Any] = {"tag": expr.tag}

        if expr.tag == "integer-constant":
            expr = cast(AST.ASTIntegerConstant, expr)
            tags.append(str(expr.cvalue))
            node["value"] = str(expr.cvalue)

        elif expr.tag == "global-address":
            expr = cast(AST.ASTGlobalAddressConstant, expr)
            tags.append(str(expr.cvalue))
            args.append(self.index_expr(expr.address_expr))
            node["value"] = str(expr.cvalue)

        elif expr.tag == "string-constant":
            expr = cast(AST.ASTStringConstant, expr)
            tags.append(expr.cstr)
            tags.append(expr.string_address)
            node["cstr"] = expr.cstr
            node["va"] = expr.string_address

        elif expr.tag == "lval-expr":
            expr = cast(AST.ASTLvalExpr, expr)
            args.append(self.index_lval(expr.lval))

        elif expr.tag == "substituted-expr":
            expr = cast(AST.ASTSubstitutedExpr, expr)
            tags.append(str(expr.assign_id))
            args.extend([
                self.index_lval(expr.super_lval),
                self.index_expr(expr.substituted_expr)])
            node["assigned"] = str(expr.assign_id)

        elif expr.tag == "cast-expr":
            expr = cast(AST.ASTCastE, expr)
            tags.append(expr.cast_tgt_type)
            args.append(self.index_expr(expr.cast_expr))
            node["type"] = expr.cast_tgt_type

        elif expr.tag == "unary-op":
            expr = cast(AST.ASTUnaryOp, expr)
            tags.append(expr.op)
            args.append(self.index_expr(expr.exp1))
            node["op"] = expr.op

        elif expr.tag == "binary-op":
            expr = cast(AST.ASTBinaryOp, expr)
            tags.append(expr.op)
            args.extend([
                self.index_expr(expr.exp1), self.index_expr(expr.exp2)])
            node["op"] = expr.op

        elif expr.tag == "question":
            expr = cast(AST.ASTQuestion, expr)
            args.extend([
                self.index_expr(expr.exp1),
                self.index_expr(expr.exp2),
                self.index_expr(expr.exp3)])

        elif expr.tag == "address-of":
            expr = cast(AST.ASTAddressOf, expr)
            args.append(self.index_lval(expr.lval))

        else:
            raise Exception("Unexpected expr tag: " + expr.tag)

        return self.add(tags, args, node)
            
            
