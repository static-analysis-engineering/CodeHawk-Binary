# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2023  Aarno Labs LLC
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
"""Basic block in an abstract syntax tree."""

from typing import Dict, List, Optional, Set, TYPE_CHECKING

import chb.ast.ASTNode as AST

from chb.astinterface.ASTInterfaceInstruction import ASTInterfaceInstruction


if TYPE_CHECKING:
    from chb.app.BasicBlock import BasicBlock
    from chb.astinterface.ASTInterface import ASTInterface


class ASTInterfaceBasicBlock:

    def __init__(self, b: "BasicBlock") -> None:
        self._b = b
        self._instructions: Dict[str, ASTInterfaceInstruction] = {}

    @property
    def basicblock(self) -> "BasicBlock":
        return self._b

    @property
    def instructions(self) -> Dict[str, ASTInterfaceInstruction]:
        if len(self._instructions) == 0:
            for (iaddr, instr) in self.basicblock.instructions.items():
                self._instructions[iaddr] = ASTInterfaceInstruction(instr)
        return self._instructions

    @property
    def has_return(self) -> bool:
        return self.basicblock.has_return

    @property
    def last_instruction(self) -> ASTInterfaceInstruction:
        bb_lastinstr = self.basicblock.last_instruction
        iaddr = bb_lastinstr.iaddr
        return self.instructions[iaddr]

    def assembly_ast_condition(
            self,
            astree: "ASTInterface",
            reverse: bool = False) -> Optional[AST.ASTExpr]:
        return self.last_instruction.assembly_ast_condition(astree, reverse=reverse)

    def ast_condition(
            self,
            astree: "ASTInterface",
            reverse: bool = False) -> Optional[AST.ASTExpr]:
        return self.last_instruction.ast_condition(astree, reverse=reverse)

    '''
    def ast_switch_condition(
            self, astree: "ASTInterface") -> Optional[AST.ASTExpr]:
        return self.last_instruction.ast_switch_condition(astree)
    '''

    def assembly_ast(self, astree: "ASTInterface") -> AST.ASTStmt:
        instrs: List[AST.ASTInstruction] = []
        for (a, i) in sorted(self.instructions.items(), key=lambda p: p[0]):
            instrs.extend(i.assembly_ast(astree))
        return astree.mk_instr_sequence(instrs)

    def ast(self, astree: "ASTInterface") -> AST.ASTStmt:
        instrs: List[AST.ASTInstruction] = []
        for (a, i) in sorted(self.instructions.items(), key=lambda p: p[0]):
            instrs.extend(i.ast(astree))
        return astree.mk_instr_sequence(instrs)
