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
"""Abstract super class for visitors on ASTNodes. """


from abc import ABC, abstractmethod

import chb.app.ASTNode as AST


class ASTVisitor(ABC):

    def __init__(self) -> None:
        pass

    @abstractmethod
    def visit_return_stmt(self, returnstmt: AST.ASTReturn) -> None:
        ...

    @abstractmethod
    def visit_block_stmt(self, blockstmt: AST.ASTBlock) -> None:
        ...

    @abstractmethod
    def visit_instruction_sequence_stmt(
            self, instrseqstmt: AST.ASTInstrSequence) -> None:
        ...

    @abstractmethod
    def visit_branch_stmt(self, branchstmt: AST.ASTBranch) -> None:
        ...

    @abstractmethod
    def visit_assign_instr(self, assigninstr: AST.ASTAssign) -> None:
        ...

    @abstractmethod
    def visit_call_instr(self, callinstr: AST.ASTCall) -> None:
        ...

    @abstractmethod
    def visit_lval(self, lval: AST.ASTLval) -> None:
        ...

    @abstractmethod
    def visit_variable(self, var: AST.ASTVariable) -> None:
        ...

    @abstractmethod
    def visit_memref(self, memref: AST.ASTMemRef) -> None:
        ...

    @abstractmethod
    def visit_no_offset(self, nooffset: AST.ASTNoOffset) -> None:
        ...

    @abstractmethod
    def visit_field_offset(self, fieldoffset: AST.ASTFieldOffset) -> None:
        ...

    @abstractmethod
    def visit_index_offset(self, indexoffset: AST.ASTIndexOffset) -> None:
        ...

    @abstractmethod
    def visit_integer_constant(
            self, intconstant: AST.ASTIntegerConstant) -> None:
        ...

    @abstractmethod
    def visit_global_address(
            self, globalddress: AST.ASTGlobalAddressConstant) -> None:
        ...

    @abstractmethod
    def visit_string_constant(
            self, stringconstant: AST.ASTStringConstant) -> None:
        ...

    @abstractmethod
    def visit_lval_expression(self, lvalexpr: AST.ASTLvalExpr) -> None:
        ...

    @abstractmethod
    def visit_cast_expression(self, castexpr: AST.ASTCastE) -> None:
        ...

    @abstractmethod
    def visit_unary_expression(self, unopexpr: AST.ASTUnaryOp) -> None:
        ...

    @abstractmethod
    def visit_binary_expression(self, binopexpr: AST.ASTBinaryOp) -> None:
        ...

    @abstractmethod
    def visit_question_expression(self, questexpr: AST.ASTQuestion) -> None:
        ...

    @abstractmethod
    def visit_address_of_expression(self, addressof: AST.ASTAddressOf) -> None:
        ...
