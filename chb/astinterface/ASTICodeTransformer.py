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
"""Transforms from low-level to high-level code by removing instructions.

Assignment instructions are removed based on whether their left-hand side
is used later, which is, in turn, based on the def-use-high of the left-hand
side.
"""

from typing import cast, List, TYPE_CHECKING

from chb.ast.ASTIdentityTransformer import ASTIdentityTransformer
import chb.ast.ASTNode as AST

if TYPE_CHECKING:
    from chb.astinterface.ASTInterface import ASTInterface
    from chb.astinterface.ASTIProvenance import ASTIProvenance


class ASTICodeTransformer(ASTIdentityTransformer):

    def __init__(
            self,
            astinterface: "ASTInterface") -> None:
        self._astinterface = astinterface

    @property
    def astinterface(self) -> "ASTInterface":
        return self._astinterface

    @property
    def provenance(self) -> "ASTIProvenance":
        return self.astinterface.astiprovenance

    def transform_stmt(self, stmt: AST.ASTStmt) -> AST.ASTStmt:
        return stmt.transform(self)

    def transform_loop_stmt(self, stmt: AST.ASTLoop) -> AST.ASTStmt:
        newbody = stmt.body.transform(self)
        return self.astinterface.mk_loop(
            newbody, optlocationid=stmt.locationid)

    def transform_block_stmt(self, stmt: AST.ASTBlock) -> AST.ASTStmt:
        newstmts = [s.transform(self) for s in stmt.stmts]
        return self.astinterface.mk_block(
            newstmts,
            labels=stmt.labels,
            optlocationid=stmt.locationid)
        
    def transform_instruction_sequence_stmt(
            self, stmt: AST.ASTInstrSequence) -> AST.ASTStmt:
        instrs: List[AST.ASTInstruction] = []
        for instr in stmt.instructions:
            if instr.is_ast_assign:
                instr = cast(AST.ASTAssign, instr)
                if (
                        self.provenance.has_active_lval_defuse_high(instr.lhs.lvalid)
                        or self.provenance.has_lval_store(instr.lhs.lvalid)):
                    instrs.append(instr)
            else:
                instrs.append(instr)
        return self.astinterface.mk_instr_sequence(
            instrs,
            labels=stmt.labels,
            optlocationid=stmt.locationid)

    def transform_branch_stmt(self, stmt: AST.ASTBranch) -> AST.ASTStmt:
        newif = stmt.ifstmt.transform(self)
        newelse = stmt.elsestmt.transform(self)
        return self.astinterface.mk_branch(
            stmt.condition,
            newif,
            newelse,
            stmt.target_address,
            optlocationid=stmt.locationid)

    def transform_switch_stmt(self, stmt: AST.ASTSwitchStmt) -> AST.ASTStmt:
        newcases = stmt.cases.transform(self)
        return self.astinterface.mk_switch_stmt(
            stmt.switchexpr, newcases, optlocationid=stmt.locationid)
        

    
