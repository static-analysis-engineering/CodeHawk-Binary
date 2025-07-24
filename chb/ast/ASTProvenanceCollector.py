# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2025  Aarno Labs LLC
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
"""Collects stmt and instruction provenance for pir inspector."""

from typing import Dict, List, TYPE_CHECKING

import chb.ast.ASTNode as AST
from chb.ast.ASTNOPVisitor import ASTNOPVisitor

if TYPE_CHECKING:
    from chb.ast.ASTDeserializer import ASTFunctionDeserialization


class ASTProvenanceCollector(ASTNOPVisitor):

    def __init__(self, dfn: "ASTFunctionDeserialization") -> None:
        self._dfn = dfn
        self._hl_ll_instr_mapping: Dict[int, List[int]] = {}

    @property
    def dfn(self) -> "ASTFunctionDeserialization":
        return self._dfn

    @property
    def provenance(self) -> Dict[int, List[AST.ASTInstruction]]:
        result: Dict[int, List[AST.ASTInstruction]] = {}
        for hlinstrid in self._hl_ll_instr_mapping:
            llinstrids = self._hl_ll_instr_mapping[hlinstrid]
            result[hlinstrid] = [self.dfn.get_instruction(i) for i in llinstrids]
        return result

    def instruction_provenance(
            self, stmt: AST.ASTStmt) -> Dict[int, List[AST.ASTInstruction]]:
        stmt.accept(self)
        return self.provenance

    def visit_loop_stmt(self, stmt: AST.ASTLoop) -> None:
        stmt.body.accept(self)

    def visit_block_stmt(self, stmt: AST.ASTBlock) -> None:
        for s in stmt.stmts:
            s.accept(self)

    def visit_instruction_sequence_stmt(self, stmt: AST.ASTInstrSequence) -> None:
        for i in stmt.instructions:
            if i.instrid in self.dfn.astree.provenance.instruction_mapping:
                self._hl_ll_instr_mapping[i.instrid] = (
                    self.dfn.astree.provenance.instruction_mapping[i.instrid])

    def visit_branch_stmt(self, stmt: AST.ASTBranch) -> None:
        stmt.ifstmt.accept(self)
        stmt.elsestmt.accept(self)
