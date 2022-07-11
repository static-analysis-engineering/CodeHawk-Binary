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

from typing import Optional


from chb.app.Function import Function

from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree
from chb.ast.ASTFunction import ASTFunction
from chb.ast.ASTNode import ASTStmt, ASTVarInfo
from chb.ast.CustomASTSupport import CustomASTSupport

from chb.astinterface.ASTInterface import ASTInterface
from chb.astinterface.CHBASTSupport import CHBASTSupport

import chb.util.fileutil as UF


class ASTInterfaceFunction(ASTFunction):

    def __init__(
            self,
            faddr: str,
            fname: str,
            f: Function,
            function_prototype: Optional[ASTVarInfo] = None) -> None:
        ASTFunction.__init__(self, faddr, fname, function_prototype)
        self._function = f

    def function_prototype(self) -> ASTVarInfo:
        if self._function_prototype is not None:
            return self._function_prototype
        else:
            raise UF.CHBError(
                "Function " + self.name + " does not have a function prototype")

    @property
    def function(self) -> Function:
        return self._function

    def ast(self,
            astree: AbstractSyntaxTree,
            support: CustomASTSupport) -> ASTStmt:
        astinterface = ASTInterface(astree)
        return self.function.ast(astinterface)
        
        
    
