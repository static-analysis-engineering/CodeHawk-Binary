# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2025  Aarno Labs LLC
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

from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.astinterface.ASTInterface import ASTInterface
    from chb.astinterface.ASTIProvenance import ASTIProvenance


class ASTICodeTransformer(ASTIdentityTransformer):

    def __init__(
            self,
            astinterface: "ASTInterface",
            variablesused: List[str] = []) -> None:
        self._astinterface = astinterface
        self._variablesused = variablesused
        chklogger.logger.info(
            "ASTICodeTransformer: variables used: [%s]",
            ", ".join(self._variablesused))

    @property
    def astinterface(self) -> "ASTInterface":
        return self._astinterface

    @property
    def provenance(self) -> "ASTIProvenance":
        return self.astinterface.astiprovenance

    @property
    def variables_used(self) -> List[str]:
        return self._variablesused

    def transform_stmt(self, stmt: AST.ASTStmt) -> AST.ASTStmt:
        return stmt.transform(self)

    def transform_loop_stmt(self, stmt: AST.ASTLoop) -> AST.ASTStmt:
        newbody = stmt.body.transform(self)
        return self.astinterface.mk_loop(
            newbody, mergeaddr=stmt.breakaddr, continueaddr=stmt.continueaddr,
            optlocationid=stmt.locationid)

    def transform_block_stmt(self, stmt: AST.ASTBlock) -> AST.ASTStmt:
        newstmts: List[AST.ASTStmt] = []
        for s in stmt.stmts:
            newstmt = s.transform(self)
            # prune empty blocks that may have been created by the pruning
            # of redundant if statements.
            # StmtLabels may be intermixed with statements, hence the check
            # for is_stmt_label.
            if (
                    not newstmt.is_stmt_label
                    and newstmt.is_ast_block
                    and len((cast(AST.ASTBlock, newstmt)).stmts) == 0):
                continue
            newstmts.append(newstmt)

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
                        self.astinterface.has_ssa_value(str(instr.lhs))
                        and not self.provenance.has_expose_instruction(instr.instrid)):
                    chklogger.logger.info(
                        "Remove [%s]: has ssa value: %s",
                        str(instr), str(self.astinterface.get_ssa_value(str(instr.lhs))))
                elif self.provenance.has_lval_store(instr.lhs.lvalid):
                    chklogger.logger.info(
                        "Transform [%s]: lval_store", str(instr))
                    instrs.append(instr)
                elif self.provenance.has_expose_instruction(instr.instrid):
                    chklogger.logger.info(
                        "Transform [%s]: expose instruction", str(instr))
                    instrs.append(instr)
                elif instr.lhs.lhost.is_global:
                    chklogger.logger.info(
                        "Transform [%s]: global lhs", str(instr))
                    instrs.append(instr)
                elif str(instr.lhs) not in self.variables_used:
                    chklogger.logger.info(
                        "Remove [%s]: lhs is not used: %s", str(instr), str(instr.lhs))
                elif self.provenance.has_active_lval_defuse_high(instr.lhs.lvalid):
                    chklogger.logger.info(
                        "Transform [%s]: active lval_defuse_high: %s",
                        str(instr),
                        self.provenance.active_lval_defuse_high(instr.lhs.lvalid))
                    instrs.append(instr)
                else:
                    chklogger.logger.info("Transform [%s]: remove (by default)", str(instr))
            else:
                chklogger.logger.info(
                    "Transform [%s]: include by default", str(instr))
                instrs.append(instr)
        return self.astinterface.mk_instr_sequence(
            instrs,
            labels=stmt.labels,
            optlocationid=stmt.locationid)

    def transform_branch_stmt(self, stmt: AST.ASTBranch) -> AST.ASTStmt:
        newif = stmt.ifstmt.transform(self)
        newelse = stmt.elsestmt.transform(self)
        if newif.is_empty() and newelse.is_empty():
            return self.astinterface.mk_block([])

        return self.astinterface.mk_branch(
            stmt.condition,
            newif,
            newelse,
            stmt.target_address,
            mergeaddr=stmt.merge_address,
            optlocationid=stmt.locationid,
            predicated=stmt.predicated)

    def transform_switch_stmt(self, stmt: AST.ASTSwitchStmt) -> AST.ASTStmt:
        newcases = stmt.cases.transform(self)
        return self.astinterface.mk_switch_stmt(
            stmt.switchexpr,
            newcases,
            stmt.merge_address,
            optlocationid=stmt.locationid)
