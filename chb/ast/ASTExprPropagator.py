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
"""Performs forward propagation of variable definitions."""

from typing import cast, Dict, List, Mapping, Sequence, Set, Tuple, TYPE_CHECKING

import chb.ast.ASTNode as AST
from chb.ast.ASTNOPVisitor import ASTNOPVisitor
from chb.ast.ASTTransformer import ASTTransformer

import chb.util.fileutil as UF



class UseDef:
    """Holds a mapping from variables to (label * expr) tuples on node entry.

    These definitions are used for replacement, hence only one definition is
    allowed.

    This object is immutable.
    """

    def __init__(
            self,
            defs: Mapping[str, Tuple[int, AST.ASTLval, AST.ASTExpr]]) -> None:
        self._defs = defs

    @property
    def defs(self) -> Mapping[str, Tuple[int, AST.ASTLval, AST.ASTExpr]]:
        return self._defs

    @property
    def variables(self) -> Sequence[str]:
        return list(self.defs.keys())

    def has_name(self, v: str) -> bool:
        return v in self.defs

    def has_stack_variable(self) -> bool:
        return any(v.startswith("localvar_") for v in self.defs)

    def get(self, v: str) -> Tuple[int, AST.ASTLval, AST.ASTExpr]:
        if v in self.defs:
            return self.defs[v]
        else:
            raise Exception("Variable: " + v + " not found in usedef")

    def apply_assign(
            self,
            instrid: int,
            lval: AST.ASTLval,
            gendef: AST.ASTExpr) -> "UseDef":

        # print("Apply assign: " + str(lval) + " := " + str(gendef))

        kill = str(lval)

        if not lval.is_variable:        # some protection against aliasing
            return UseDef(self.defs)    # needs to be strengthened

        if kill not in self.defs:
            if kill in gendef.use():             # nothing to add or remove
                return UseDef(self.defs)

        usedefs: Dict[str, Tuple[int, AST.ASTLval, AST.ASTExpr]] = {}
        if kill not in self.defs:
            usedefs[kill] = (instrid, lval, gendef)

        for v in self.defs:
            if v == kill and v in gendef.use():
                pass    # remove from usedefs
            elif v == kill:
                usedefs[v] = (instrid, lval, gendef)    # replace
            elif (
                    kill not in self.defs[v][1].use()
                    and kill not in self.defs[v][2].use()):
                usedefs[v] = self.defs[v]         # keep this def
            else:
                pass   # leave out this def

        return UseDef(usedefs)

    def apply_call(self, kill: Sequence[str]) -> "UseDef":
        usedefs: Dict[str, Tuple[int, AST.ASTLval, AST.ASTExpr]] = {}
        for v in self.defs:
            if v in kill:
                pass   # remove from usedefs
            else:
                for k in kill:
                    if k in self.defs[v][1].use():
                        break         # remove from usedefs
                else:
                    usedefs[v] = self.defs[v]    # keep this def

        return UseDef(usedefs)

    def join(self, other: "UseDef") -> "UseDef":

        # only keep definitions that are shared
        if len(other.defs) == 0 or len(self.defs) == 0:
            return UseDef({})

        newdefs: Dict[str, Tuple[int, AST.ASTLval, AST.ASTExpr]] = {}
        for v in self.defs:
            if v in other.defs:
                if self.defs[v][0] == other.defs[v][0]:
                    newdefs[v] = self.defs[v]

        return UseDef(newdefs)

    def __str__(self) -> str:
        lines: List[str] = []
        for (name, (i, lv, x)) in self.defs.items():
            ctype = str(lv.ctype) + " " if lv.ctype else ""
            lines.append(ctype + name + ": " + str(x))
        return "\n".join(lines)


class ASTUseDefs(ASTNOPVisitor):
    """Computes usedefs by forward propagation through the AST."""

    def __init__(self) -> None:
        self._instrdefs: Dict[int, UseDef] = {}
        self._usedefs = UseDef({})  # usedefs on entry to the current stmt/instr
        self._addresstaken: Set[str] = set([])

    @property
    def instrdefs(self) -> Dict[int, UseDef]:
        return self._instrdefs

    @property
    def usedefs(self) -> UseDef:
        return self._usedefs

    @property
    def addresstaken(self) -> Set[str]:
        return self._addresstaken

    def set_instr_usedefs(self, id: int, ud: UseDef) -> None:
        self._instrdefs[id] = ud

    def set_usedefs(self, ud: UseDef) -> None:
        self._usedefs = ud

    def get_usedefs(self, stmt: AST.ASTStmt) -> Dict[int, UseDef]:
        self._addresstaken = stmt.address_taken()
        self.stmt_usedefs(stmt)
        return self.instrdefs
    
    def stmt_usedefs(self, stmt: AST.ASTStmt) -> None:
        if stmt.is_ast_return:
            pass

        elif stmt.is_ast_block:
            self.visit_block_stmt(cast(AST.ASTBlock, stmt))

        elif stmt.is_ast_instruction_sequence:
            self.visit_instruction_sequence_stmt(cast(AST.ASTInstrSequence, stmt))

        elif stmt.is_ast_branch:
            self.visit_branch_stmt(cast(AST.ASTBranch, stmt))

        else:
            raise UF.CHBError("Statement type not recognized: " + stmt.tag)

    def visit_block_stmt(self, stmt: AST.ASTBlock) -> None:
        self.set_instr_usedefs(stmt.stmtid, self.usedefs)
        for s in stmt.stmts:
            s.accept(self)

    def visit_instruction_sequence_stmt(self, stmt: AST.ASTInstrSequence) -> None:
        self.set_instr_usedefs(stmt.stmtid, self.usedefs)        
        for i in stmt.instructions:
            i.accept(self)

    def visit_branch_stmt(self, stmt: AST.ASTBranch) -> None:
        self.set_instr_usedefs(stmt.stmtid, self.usedefs)        
        stmt.ifstmt.accept(self)
        ifusedefs = self.usedefs
        stmt.elsestmt.accept(self)
        elseusedefs = self.usedefs
        self.set_usedefs(ifusedefs.join(elseusedefs))

    def visit_assign_instr(self, instr: AST.ASTAssign) -> None:
        self.set_instr_usedefs(instr.instrid, self.usedefs)
        usedefs_x = self.usedefs.apply_assign(instr.instrid, instr.define(), instr.rhs)
        self.set_usedefs(usedefs_x)

    def visit_call_instr(self, instr: AST.ASTCall) -> None:
        self.set_instr_usedefs(instr.instrid, self.usedefs)        
        kill = [str(k) for k in instr.kill()] + list(self.addresstaken)
        usedefs_x = self.usedefs.apply_call(kill)
        self.set_usedefs(usedefs_x)
                                  

class ASTExprPropagator(ASTTransformer):

    def __init__(self) -> None:
        self._instrusedefs: Dict[int, UseDef] = {}
        self._currentid: int = 0

    @property
    def instrusedefs(self) -> Dict[int, UseDef]:
        return self._instrusedefs

    @property
    def currentid(self) -> int:
        return self._currentid

    def set_currentid(self, id: int) -> None:
        self._currentid = id

    def instrusedefs_set(self, id: int, usedef: UseDef) -> None:
        self._instrusedefs[id] = usedef

    def instrusedefs_has(self, id: int) -> bool:
        return id in self.instrusedefs

    def instrusedefs_get(self, id: int) -> UseDef:
        if id in self.instrusedefs:
            return self.instrusedefs[id]
        else:
            raise UF.CHBError("No use-def found for id: " + str(id))

    def propagate(self, stmt: AST.ASTStmt) -> AST.ASTStmt:
        stmtusedefs = ASTUseDefs()
        self._instrusedefs = stmtusedefs.get_usedefs(stmt)
        return self.transform_stmt(stmt)

    def transform_stmt(self, stmt: AST.ASTStmt) -> AST.ASTStmt:
        if stmt.is_ast_return:
            return self.transform_return_stmt(cast(AST.ASTReturn, stmt))

        elif stmt.is_ast_block:
            return self.transform_block_stmt(cast(AST.ASTBlock, stmt))

        elif stmt.is_ast_instruction_sequence:
            return self.transform_instruction_sequence_stmt(
                cast(AST.ASTInstrSequence, stmt))

        elif stmt.is_ast_branch:
            return self.transform_branch_stmt(cast(AST.ASTBranch, stmt))

        else:
            raise UF.CHBError("Statement type not recognized: " + stmt.tag)

    def transform_return_stmt(self, stmt: AST.ASTReturn) -> AST.ASTStmt:
        self.set_currentid(stmt.stmtid)
        if stmt.has_return_value():
            return AST.ASTReturn(stmt.stmtid, stmt.expr.transform(self))
        else:
            return stmt

    def transform_block_stmt(self, stmt: AST.ASTBlock) -> AST.ASTStmt:
        self.set_currentid(stmt.stmtid)        
        return AST.ASTBlock(
            stmt.stmtid, [s.transform(self) for s in stmt.stmts])

    def transform_instruction_sequence_stmt(
            self, stmt: AST.ASTInstrSequence) -> AST.ASTStmt:
        self.set_currentid(stmt.stmtid)        
        return AST.ASTInstrSequence(
            stmt.stmtid, [i.transform(self) for i in stmt.instructions])

    def transform_branch_stmt(self, stmt: AST.ASTBranch) -> AST.ASTStmt:
        self.set_currentid(stmt.stmtid)
        newcondition = stmt.condition.transform(self)
        newifstmt = stmt.ifstmt.transform(self)
        self.set_currentid(stmt.stmtid)
        newelsestmt = stmt.elsestmt.transform(self)
        return AST.ASTBranch(
            stmt.stmtid,
            newcondition,
            newifstmt,
            newelsestmt,
            stmt.relative_offset)

    def transform_assign_instr(self, instr: AST.ASTAssign) -> AST.ASTInstruction:
        self.set_currentid(instr.instrid)
        return AST.ASTAssign(
            instr.instrid, instr.lhs.transform(self), instr.rhs.transform(self))

    def transform_call_instr(self, instr: AST.ASTCall) -> AST.ASTInstruction:
        self.set_currentid(instr.instrid)
        return AST.ASTCall(
            instr.instrid,
            instr.lhs.transform(self),
            instr.tgt.transform(self),
            [a.transform(self) for a in instr.arguments])

    def transform_lval(self, lval: AST.ASTLval) -> AST.ASTLval:
        return AST.ASTLval(
            cast(AST.ASTLHost, lval.lhost.transform(self)),
            cast(AST.ASTOffset, lval.offset.transform(self)))

    def transform_variable(self, var: AST.ASTVariable) -> AST.ASTLHost:
        return var

    def transform_memref(self, memref: AST.ASTMemRef) -> AST.ASTLHost:
        return AST.ASTMemRef(memref.memexp.transform(self))

    def transform_no_offset(self, offset: AST.ASTNoOffset) -> AST.ASTOffset:
        return offset

    def transform_field_offset(
            self, offset: AST.ASTFieldOffset) -> AST.ASTOffset:
        return AST.ASTFieldOffset(
            offset.fieldname, offset.fieldtype, offset.offset.transform(self))

    def transform_index_offset(
            self, offset: AST.ASTIndexOffset) -> AST.ASTOffset:
        return AST.ASTIndexOffset(
            offset.index.transform(self), offset.offset.transform(self))

    def transform_integer_constant(
            self, expr: AST.ASTIntegerConstant) -> AST.ASTExpr:
        return expr

    def transform_global_address(
            self, expr: AST.ASTGlobalAddressConstant) -> AST.ASTExpr:
        return expr

    def transform_string_constant(
            self, expr: AST.ASTStringConstant) -> AST.ASTExpr:
        return expr

    def transform_lval_expression(self, expr: AST.ASTLvalExpr) -> AST.ASTExpr:
        name = str(expr.lval)
        id = self.currentid
        if self.instrusedefs_has(id):
            usedefs = self.instrusedefs_get(id)
            if usedefs.has_name(name):
                (assign_id, lval, newexpr) = usedefs.get(name)
                if name in newexpr.use():
                    # Don't replace variable if it occurs in expression
                    return expr
                else:
                    return AST.ASTSubstitutedExpr(expr.lval, assign_id, newexpr)
            else:
                return AST.ASTLvalExpr(expr.lval.transform(self))
        else:
            return AST.ASTLvalExpr(expr.lval.transform(self))

    def transform_cast_expression(self, expr: AST.ASTCastE) -> AST.ASTExpr:
        return AST.ASTCastE(expr.cast_tgt_type, expr.cast_expr.transform(self))

    def transform_unary_expression(self, expr: AST.ASTUnaryOp) -> AST.ASTExpr:
        return AST.ASTUnaryOp(expr.op, expr.exp1.transform(self))

    def transform_binary_expression(self, expr: AST.ASTBinaryOp) -> AST.ASTExpr:
        return AST.ASTBinaryOp(
            expr.op, expr.exp1.transform(self), expr.exp2.transform(self))

    def transform_question_expression(
            self, expr: AST.ASTQuestion) -> AST.ASTExpr:
        return AST.ASTQuestion(
            expr.exp1.transform(self),
            expr.exp2.transform(self),
            expr.exp3.transform(self))

    def transform_address_of_expression(
            self, expr: AST.ASTAddressOf) -> AST.ASTExpr:
        return AST.ASTAddressOf(expr.lval.transform(self))
