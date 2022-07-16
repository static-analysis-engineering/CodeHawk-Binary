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
"""Abstract class that provides the interface to populating the AST."""

from abc import ABC, abstractmethod

from typing import Optional, Tuple

from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree
from chb.ast.ASTNode import ASTStmt, ASTVarInfo
from chb.ast.CustomASTSupport import CustomASTSupport


class ASTFunction(ABC):

    def __init__(
            self,
            faddr: str,
            fname: str,
            function_prototype: Optional[ASTVarInfo] = None) -> None:
        self._address = faddr
        self._name = fname
        self._function_prototype = function_prototype

    @property
    def address(self) -> str:
        return self._address

    @property
    def name(self) -> str:
        return self._name

    def has_function_prototype(self) -> bool:
        return self._function_prototype is not None

    @abstractmethod
    def function_prototype(self) -> ASTVarInfo:
        ...

    @abstractmethod
    def ast(self, astree: AbstractSyntaxTree,
            support: CustomASTSupport) -> ASTStmt:
        ...

    @abstractmethod
    def cfg_ast(
            self, astree: AbstractSyntaxTree,
            support: CustomASTSupport) -> ASTStmt:
        ...

    @abstractmethod
    def mk_asts(
            self,
            astree: AbstractSyntaxTree,
            support: CustomASTSupport) -> Tuple[ASTStmt, ASTStmt]:
        ...
