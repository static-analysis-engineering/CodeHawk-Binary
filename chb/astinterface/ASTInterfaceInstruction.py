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
"""Instruction in an abstract syntax tree."""

from typing import Dict, List, Optional, Set, Tuple, TYPE_CHECKING

import chb.ast.ASTNode as AST


if TYPE_CHECKING:
    from chb.app.Instruction import Instruction
    from chb.astinterface.ASTInterface import ASTInterface
    from chb.invariants.XXpr import XXpr


class ASTInterfaceInstruction:

    def __init__(self, instr: "Instruction") -> None:
        self._instr = instr
        self._hl_ast_instrs: List[AST.ASTInstruction] = []
        self._ll_ast_instrs: List[AST.ASTInstruction] = []
        self._hl_ast_condition: Optional[AST.ASTExpr] = None
        self._ll_ast_condition: Optional[AST.ASTExpr] = None

    @property
    def instruction(self) -> "Instruction":
        return self._instr

    @property
    def iaddr(self) -> str:
        return self.instruction.iaddr

    @property
    def is_subsumed(self) -> bool:
        return self.instruction.is_subsumed

    def subsumed_by(self) -> str:
        return self.instruction.subsumed_by()

    @property
    def hl_ast_instructions(self) -> List[AST.ASTInstruction]:
        return self._hl_ast_instrs

    @property
    def ll_ast_instructions(self) -> List[AST.ASTInstruction]:
        return self._ll_ast_instrs

    @property
    def hl_ast_condition(self) -> Optional[AST.ASTExpr]:
        return self._hl_ast_condition

    @property
    def ll_ast_condition(self) -> Optional[AST.ASTExpr]:
        return self._ll_ast_condition

    def ast_prov(self, astree: "ASTInterface") -> None:
        if len(self.hl_ast_instructions) == 0:
            (hl, ll) = self.instruction.ast_prov(astree)
            self._hl_ast_instrs = hl
            self._ll_ast_instrs = ll

    def return_value(self) -> Optional["XXpr"]:
        return self.instruction.return_value()

    def assembly_ast(self, astree: "ASTInterface") -> List[AST.ASTInstruction]:
        if len(self.ll_ast_instructions) == 0:
            self.ast_prov(astree)
        return self.ll_ast_instructions

    def ast(self, astree: "ASTInterface") -> List[AST.ASTInstruction]:
        if len(self.hl_ast_instructions) == 0:
            self.ast_prov(astree)
        return self.hl_ast_instructions

    def assembly_ast_condition(
            self,
            astree: "ASTInterface",
            reverse: bool = False) -> Optional[AST.ASTExpr]:
        if self.ll_ast_condition is None:
            self.ast_condition_prov(astree, reverse=reverse)
        return self.ll_ast_condition

    def ast_condition(
            self,
            astree: "ASTInterface",
            reverse: bool = False) -> Optional[AST.ASTExpr]:
        if self.hl_ast_condition is None:
            self.ast_condition_prov(astree, reverse=reverse)
        return self.hl_ast_condition

    def ast_condition_prov(
            self,
            astree: "ASTInterface",
            reverse: bool = False) -> None:
        if self.hl_ast_condition is None:
            (hl, ll) = self.instruction.ast_condition_prov(astree, reverse=reverse)
        self._hl_ast_condition = hl
        self._ll_ast_condition = ll

    def ast_case_expression(
            self, target: str, astree: "ASTInterface") -> Optional[AST.ASTExpr]:
        return self.instruction.ast_case_expression(target, astree)
