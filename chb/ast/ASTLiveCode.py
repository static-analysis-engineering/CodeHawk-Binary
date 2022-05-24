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
"""Identifies live assignments and statements in an AST."""

from typing import cast, Dict, Mapping, Set

import chb.ast.ASTNode as AST
from chb.ast.ASTNOPVisitor import ASTNOPVisitor

import chb.util.fileutil as UF


class ASTLiveCode(ASTNOPVisitor):

    def __init__(self) -> None:
        self._livestmts: Set[int] = set([])
        self._liveinstrs: Set[int] = set([])
        self._livesymbols: Set[str] = set([])
        self._live_on_exit: Dict[int, Set[str]] = {}
        self._live_x: Set[str] = set([])  # live variables on exit for next instr

    @property
    def livestmts(self) -> Set[int]:
        return self._livestmts

    @property
    def liveinstrs(self) -> Set[int]:
        return self._liveinstrs

    @property
    def livesymbols(self) -> Set[str]:
        return self._livesymbols

    @property
    def livecode(self) -> Set[int]:
        return (self.livestmts | self.liveinstrs)

    @property
    def live_on_exit(self) -> Dict[int, Set[str]]:
        return self._live_on_exit

    def set_live_on_exit(self, id: int, s: Set[str]) -> None:
        self._live_on_exit[id] = s

    @property
    def live_x(self) -> Set[str]:
        return self._live_x

    def set_live_x(self, s: Set[str]) -> None:
        self._live_x = s

    def live_variables_on_entry(self, stmt: AST.ASTStmt) -> None:
        """Compute the live variables at node entry given live variables at node exit.

        Record live_on_exit along the way.
        """
        stmt.accept(self)

    def visit_return_stmt(self, stmt: AST.ASTReturn) -> None:
        self.set_live_on_exit(stmt.stmtid, set([]))
        if stmt.has_return_value():
            self.set_live_x(set(stmt.expr.use()))
        else:
            self.set_live_x(set([]))
        self._livestmts.add(stmt.stmtid)

    def visit_block_stmt(self, stmt: AST.ASTBlock) -> None:
        self.set_live_on_exit(stmt.stmtid, self.live_x)
        for s in reversed(stmt.stmts):
            s.accept(self)
        if any(s.stmtid in self.livestmts for s in stmt.stmts):
            self._livestmts.add(stmt.stmtid)

    def visit_instruction_sequence_stmt(self, stmt: AST.ASTInstrSequence) -> None:
        self.set_live_on_exit(stmt.stmtid, self.live_x)
        for i in reversed(stmt.instructions):
            i.accept(self)
        if any(i.instrid in self.liveinstrs for i in stmt.instructions):
            self._livestmts.add(stmt.stmtid)

    def visit_branch_stmt(self, stmt: AST.ASTBranch) -> None:
        self.set_live_on_exit(stmt.stmtid, self.live_x)
        condlive_e = set(stmt.condition.use())
        stmt.ifstmt.accept(self)
        iflive_e = self.live_x
        stmt.elsestmt.accept(self)
        elselive_e = self.live_x
        self.set_live_x((condlive_e | iflive_e) | elselive_e)
        if (
                stmt.ifstmt.stmtid in self.livestmts
                or stmt.elsestmt.stmtid in self.livestmts):
            self._livestmts.add(stmt.stmtid)

    def visit_assign_instr(self, instr: AST.ASTAssign) -> None:
        self.set_live_on_exit(instr.instrid, self.live_x)
        kill = [str(s) for s in instr.kill()]
        live_e: Set[str] = set([])
        for v in self.live_x:
            if v not in kill:
                live_e.add(v)
        if (
                instr.lhs.is_memref
                or (not instr.lhs.offset.is_no_offset)
                or instr.lhs.is_global
                or str(instr.lhs) in self.live_x):
            for v in instr.use():
                live_e.add(v)
        self.set_live_x(live_e)
        if (
                instr.lhs.is_memref
                or (not instr.lhs.offset.is_no_offset)
                or instr.lhs.is_global
                or (instr.instrid in self.live_on_exit
                    and str(instr.lhs) in self.live_on_exit[instr.instrid])):
            self._liveinstrs.add(instr.instrid)
            self._livesymbols = self._livesymbols | instr.variables_used()

    def visit_call_instr(self, instr: AST.ASTCall) -> None:
        self.set_live_on_exit(instr.instrid, self.live_x)
        kill = instr.kill()
        live_e: Set[str] = set([])
        for v in self.live_x:
            if v not in kill:
                live_e.add(v)
        for a in instr.arguments:
            for v in a.use():
                live_e.add(v)
        self.set_live_x(live_e)
        self._liveinstrs.add(instr.instrid)
        self._livesymbols = self._livesymbols | instr.variables_used()
