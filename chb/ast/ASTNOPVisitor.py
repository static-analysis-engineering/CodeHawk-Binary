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
"""Full implementation of ASTVisitor without any operations."""

import chb.ast.ASTNode as AST
from chb.ast.ASTVisitor import ASTVisitor


class ASTNOPVisitor(ASTVisitor):

    def __init__(self) -> None:
        pass

    def visit_return_stmt(self, returnstmt: AST.ASTReturn) -> None:
        pass

    def visit_block_stmt(self, blockstmt: AST.ASTBlock) -> None:
        pass

    def visit_instruction_sequence_stmt(
            self, instrseqstmt: AST.ASTInstrSequence) -> None:
        pass

    def visit_branch_stmt(self, branchstmt: AST.ASTBranch) -> None:
        pass

    def visit_assign_instr(self, assigninstr: AST.ASTAssign) -> None:
        pass

    def visit_call_instr(self, callinstr: AST.ASTCall) -> None:
        pass

    def visit_lval(self, lval: AST.ASTLval) -> None:
        pass

    def visit_variable(self, var: AST.ASTVariable) -> None:
        pass

    def visit_memref(self, memref: AST.ASTMemRef) -> None:
        pass

    def visit_no_offset(self, nooffset: AST.ASTNoOffset) -> None:
        pass

    def visit_field_offset(self, fieldoffset: AST.ASTFieldOffset) -> None:
        pass

    def visit_index_offset(self, indexoffset: AST.ASTIndexOffset) -> None:
        pass

    def visit_integer_constant(
            self, intconstant: AST.ASTIntegerConstant) -> None:
        pass

    def visit_global_address(
            self, globalddress: AST.ASTGlobalAddressConstant) -> None:
        pass

    def visit_string_constant(
            self, stringconstant: AST.ASTStringConstant) -> None:
        pass

    def visit_lval_expression(self, lvalexpr: AST.ASTLvalExpr) -> None:
        pass

    def visit_cast_expression(self, castexpr: AST.ASTCastE) -> None:
        pass

    def visit_unary_expression(self, unopexpr: AST.ASTUnaryOp) -> None:
        pass

    def visit_binary_expression(self, binopexpr: AST.ASTBinaryOp) -> None:
        pass

    def visit_question_expression(self, questexpr: AST.ASTQuestion) -> None:
        pass

    def visit_address_of_expression(self, addressof: AST.ASTAddressOf) -> None:
        pass
