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
"""Abstract class for AST transformers that transform nodes into the same type."""

from abc import ABC, abstractmethod

import chb.ast.ASTNode as AST


class ASTTransformer(ABC):

    def __init__(self) -> None:
        pass

    @abstractmethod
    def transform_return_stmt(self, returnstmt: AST.ASTReturn) -> AST.ASTStmt:
        ...

    @abstractmethod
    def transform_block_stmt(self, blockstmt: AST.ASTBlock) -> AST.ASTStmt:
        ...

    @abstractmethod
    def transform_instruction_sequence_stmt(
            self, instrseqstmt: AST.ASTInstrSequence) -> AST.ASTStmt:
        ...

    @abstractmethod
    def transform_branch_stmt(self, branchstmt: AST.ASTBranch) -> AST.ASTStmt:
        ...

    @abstractmethod
    def transform_assign_instr(self, assigninstr: AST.ASTAssign) -> AST.ASTInstruction:
        ...

    @abstractmethod
    def transform_call_instr(self, callinstr: AST.ASTCall) -> AST.ASTInstruction:
        ...

    @abstractmethod
    def transform_lval(self, lval: AST.ASTLval) -> AST.ASTLval:
        ...

    @abstractmethod
    def transform_variable(self, var: AST.ASTVariable) -> AST.ASTLHost:
        ...

    @abstractmethod
    def transform_memref(self, var: AST.ASTMemRef) -> AST.ASTLHost:
        ...

    @abstractmethod
    def transform_no_offset(self, offset: AST.ASTNoOffset) -> AST.ASTOffset:
        ...

    @abstractmethod
    def transform_field_offset(
            self, offset: AST.ASTFieldOffset) -> AST.ASTOffset:
        ...

    @abstractmethod
    def transform_index_offset(
            self, offset: AST.ASTIndexOffset) -> AST.ASTOffset:
        ...

    @abstractmethod
    def transform_integer_constant(
            self, intconstant: AST.ASTIntegerConstant) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_global_address(
            self, globaladdr: AST.ASTGlobalAddressConstant) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_string_constant(
            self, stringconstant: AST.ASTStringConstant) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_lval_expression(
            self, lvalexpr: AST.ASTLvalExpr) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_cast_expression(self, castexpr: AST.ASTCastE) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_unary_expression(self, unop: AST.ASTUnaryOp) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_binary_expression(self, binop: AST.ASTBinaryOp) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_question_expression(self, qexpr: AST.ASTQuestion) -> AST.ASTExpr:
        ...

    @abstractmethod
    def transform_address_of_expression(
            self, addressof: AST.ASTAddressOf) -> AST.ASTExpr:
        ...
