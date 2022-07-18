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
from chb.ast.CustomASTSupport import CustomASTSupport

from chb.astinterface.ASTInterfaceBasicBlock import ASTInterfaceBasicBlock
from chb.astinterface.ASTInterface import ASTInterface
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
            function_prototype: Optional[ASTVarInfo] = None) -> None:
        ASTFunction.__init__(self, faddr, fname, function_prototype)
        self._function = f
        self._astinterface: Optional[ASTInterface] = None
        self._blocks: Dict[str, ASTInterfaceBasicBlock] = {}

    @property
    def blocks(self) -> Dict[str, ASTInterfaceBasicBlock]:
        return self._blocks

    @property
    def astinterface(self) -> Optional[ASTInterface]:
        return self._astinterface

    def function_prototype(self) -> ASTVarInfo:
        if self._function_prototype is not None:
            return self._function_prototype
        else:
            raise UF.CHBError(
                "Function " + self.name + " does not have a function prototype")

    @property
    def function(self) -> "Function":
        return self._function

    def block(self, startaddr: str) -> ASTInterfaceBasicBlock:
        if not startaddr in self.blocks:
            astblock = ASTInterfaceBasicBlock(self.function.blocks[startaddr])
            self.blocks[startaddr] = astblock
        return self.blocks[startaddr]

    def ast(self,
            astree: AbstractSyntaxTree,
            support: CustomASTSupport) -> ASTStmt:
        if self.astinterface is not None:
            return self.function.cfg.ast(self, self.astinterface)
        else:
            raise Exception("should not happen")

    def cfg_ast(
            self,
            astree: AbstractSyntaxTree,
            support: CustomASTSupport) -> ASTStmt:
        if self.astinterface is not None:
            return self.function.cfg.cfg_ast(self, self.astinterface)
        else:
            raise Exception("should not happen")

    def mk_asts(
            self,
            astree: AbstractSyntaxTree,
            support: CustomASTSupport) -> Tuple[ASTStmt, ASTStmt]:
        self._astinterface = ASTInterface(astree)
        if self.astinterface is not None:
            highlevel = self.mk_high_level_ast(self.astinterface, support)
            lowlevel  = self.mk_low_level_ast(self.astinterface, support)
            for (hlid, llids) in self.instruction_mapping().items():
                astree.addto_instruction_mapping(hlid, llids)
            return (highlevel, lowlevel)
        else:
            raise Exception("should not happen")

    def mk_low_level_ast(
            self,
            astinterface: ASTInterface,
            support: CustomASTSupport) -> ASTStmt:
        return self.function.cfg.cfg_ast(self, astinterface)

    def mk_high_level_ast(
            self,
            astinterface: ASTInterface,
            support: CustomASTSupport) -> ASTStmt:
        return self.function.cfg.ast(self, astinterface)

    def instruction_mapping(self) -> Dict[int, List[int]]:
        result: Dict[int, List[int]] = {}
        if self.astinterface is not None:
            for b in self.blocks.values():
                result.update(b.instruction_mapping(self.astinterface))
            return result
        else:
            raise Exception("ASTInterface has not yet been created.""")
