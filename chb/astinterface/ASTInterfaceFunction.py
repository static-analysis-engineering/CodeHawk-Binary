# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022 Aarno Labs, LLC
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
"""Function interface for AST construction."""

from typing import cast, Dict, List, Optional, Set, Tuple, TYPE_CHECKING


from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree
from chb.ast.ASTFunction import ASTFunction
from chb.ast.ASTNode import ASTStmt, ASTVarInfo
from chb.ast.ASTCPrettyPrinter import ASTCPrettyPrinter
from chb.ast.CustomASTSupport import CustomASTSupport

from chb.astinterface.ASTICodeTransformer import ASTICodeTransformer
from chb.astinterface.ASTICPrettyPrinter import ASTICPrettyPrinter
from chb.astinterface.ASTInterface import ASTInterface
from chb.astinterface.ASTInterfaceBasicBlock import ASTInterfaceBasicBlock
from chb.astinterface.ASTInterfaceInstruction import ASTInterfaceInstruction
from chb.astinterface.CHBASTSupport import CHBASTSupport

import chb.util.fileutil as UF


if TYPE_CHECKING:
    from chb.app.BasicBlock import BasicBlock
    from chb.app.Function import Function


class ASTInterfaceFunction(ASTFunction):

    def __init__(
            self,
            faddr: str,
            fname: str,
            f: "Function",
            astinterface: ASTInterface) -> None:
        ASTFunction.__init__(self, faddr, fname)
        self._function = f
        self._astinterface = astinterface
        self._astblocks: Dict[str, ASTInterfaceBasicBlock] = {}
        self._astinstructions: Dict[str, ASTInterfaceInstruction] = {}

    @property
    def astblocks(self) -> Dict[str, ASTInterfaceBasicBlock]:
        if len(self._astblocks) == 0:
            for (addr, block) in self.function.blocks.items():
                astblock = ASTInterfaceBasicBlock(block)
                self._astblocks[addr] = astblock
        return self._astblocks

    @property
    def astinstructions(self) -> Dict[str, ASTInterfaceInstruction]:
        if len(self._astinstructions) == 0:
            for block in self.astblocks.values():
                for (iaddr, instr) in block.instructions.items():
                    self._astinstructions[iaddr] = instr
        return self._astinstructions

    @property
    def astinterface(self) -> ASTInterface:
        return self._astinterface

    @property
    def function(self) -> "Function":
        return self._function

    @property
    def verbose(self) -> bool:
        return self.astinterface.verbose

    def astblock(self, startaddr: str) -> ASTInterfaceBasicBlock:
        return self.astblocks[startaddr]

    def ast(self, support: CustomASTSupport) -> ASTStmt:
        return self.function.cfg.ast(self, self.astinterface)

    def cfg_ast(self, support: CustomASTSupport) -> ASTStmt:
        return self.function.cfg.cfg_ast(self, self.astinterface)

    def mk_asts(self, support: CustomASTSupport) -> List[ASTStmt]:
        highlevel = self.mk_high_level_ast(support)
        lowlevel  = self.mk_low_level_ast(support)
        return highlevel + [lowlevel]

    def mk_low_level_ast(
            self,
            support: CustomASTSupport) -> ASTStmt:
        return self.function.cfg.cfg_ast(self, self.astinterface)

    def mk_high_level_ast(
            self,
            support: CustomASTSupport) -> List[ASTStmt]:
        ast = self.function.cfg.ast(self, self.astinterface)

        self.complete_instruction_connections()

        if self.verbose:
            iprettyprinter = ASTICPrettyPrinter(
                self.astinterface.symboltable,
                self.astinterface.provenance)
            print(iprettyprinter.to_c(ast))

        codetransformer = ASTICodeTransformer(self.astinterface)
        transformedcode = codetransformer.transform_stmt(ast)

        if self.verbose:
            prettyprinter = ASTCPrettyPrinter(self.astinterface.symboltable)
            print("\n\nTransformed code")
            print(prettyprinter.to_c(transformedcode))
            print("\n\nDiagnostics")
            print("\n".join(self.astinterface.diagnostics))

        return [transformedcode, ast]

    def complete_instruction_connections(self) -> None:
        """Connect hl-instrs to the ll-instrs subsumed by them."""

        for instr in self.astinstructions.values():
            if instr.is_subsumed:
                subsumeraddr = instr.subsumed_by()
                subsumerinstr = self.astinstructions[subsumeraddr]
                for hl_instr in subsumerinstr.hl_ast_instructions:
                    for ll_instr in instr.ll_ast_instructions:
                        self.astinterface.add_instr_mapping(hl_instr, ll_instr)
