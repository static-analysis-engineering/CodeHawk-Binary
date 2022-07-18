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

from typing import Dict, List, Optional, Set, TYPE_CHECKING

import chb.ast.ASTNode as AST


if TYPE_CHECKING:
    from chb.app.Instruction import Instruction
    from chb.astinterface.ASTInterface import ASTInterface
    from chb.invariants.XXpr import XXpr


class ASTInterfaceInstruction:

    def __init__(self, instr: "Instruction") -> None:
        self._instr = instr
        self._ast_instrs: List[AST.ASTInstruction] = []
        self._assembly_ast_instrs: List[AST.ASTInstruction] = []

    @property
    def instruction(self) -> "Instruction":
        return self._instr

    @property
    def ast_instructions(self) -> List[AST.ASTInstruction]:
        return self._ast_instrs

    @property
    def assembly_ast_instructions(self) -> List[AST.ASTInstruction]:
        return self._assembly_ast_instrs

    def return_value(self) -> Optional["XXpr"]:
        return self.instruction.return_value()

    def assembly_ast(self, astree: "ASTInterface") -> List[AST.ASTInstruction]:
        if len(self.assembly_ast_instructions) == 0:
            self._assembly_ast_instrs = self.instruction.assembly_ast(astree)
        return self.assembly_ast_instructions

    def ast(self, astree: "ASTInterface") -> List[AST.ASTInstruction]:
        if len(self.ast_instructions) == 0:
            self._ast_instrs = self.instruction.ast(astree)
        return self.ast_instructions

    def instruction_mapping(self, astree: "ASTInterface") -> Dict[int, List[int]]:
        result: Dict[int, List[int]] = {}
        lowlevelinstrs = self.assembly_ast(astree)
        highlevelinstrs = self.ast(astree)
        if len(lowlevelinstrs) == len(highlevelinstrs):
            for (high, low) in zip(highlevelinstrs, lowlevelinstrs):
                result[high.instrid] = [low.instrid]
        elif len(highlevelinstrs) == 1:
            high = highlevelinstrs[0]
            result[high.instrid] = [i.instrid for i in lowlevelinstrs]
        elif len(highlevelinstrs) == 0:
            pass
        else:
            raise Exception(
                "Instruction "
                + str(self.instruction)
                + " has "
                + str(len(highlevelinstrs))
                + " high-level instructions and "
                + str(len(lowlevelinstrs))
                + " low-level instructions")
        return result
                      
    def assembly_ast_condition(
            self,
            astree: "ASTInterface",
            reverse: bool = False) -> Optional[AST.ASTExpr]:
        return self.instruction.assembly_ast_condition(astree, reverse=reverse)

    def ast_case_expression(
            self, target: str, astree: "ASTInterface") -> Optional[AST.ASTExpr]:
        return self.instruction.ast_case_expression(target, astree)
