# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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
"""Operand of an ARM assembly instruction."""

from typing import List, Optional, Tuple, TYPE_CHECKING

from chb.app.Operand import Operand

from chb.arm.ARMDictionaryRecord import ARMDictionaryRecord
from chb.arm.ARMOperandKind import ARMOperandKind

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.util.IndexedTable import IndexedTableValue

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


class ARMOperand(ARMDictionaryRecord, Operand):

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMDictionaryRecord.__init__(self, d, ixval)
        Operand.__init__(self)

    @property
    def opkind(self) -> ARMOperandKind:
        return self.armd.arm_opkind(self.args[0])

    @property
    def size(self) -> int:
        return self.opkind.size

    @property
    def is_immediate(self) -> bool:
        return self.opkind.is_immediate

    @property
    def is_absolute(self) -> bool:
        return self.opkind.is_absolute

    @property
    def value(self) -> int:
        return self.opkind.value

    @property
    def is_register(self) -> bool:
        return self.opkind.is_register

    @property
    def register(self) -> str:
        return self.opkind.register

    @property
    def is_indirect_register(self) -> bool:
        return self.opkind.is_indirect_register

    @property
    def indirect_register(self) -> str:
        return self.opkind.indirect_register

    @property
    def is_write_back(self) -> bool:
        return self.opkind.is_write_back

    @property
    def is_shifted_register(self) -> bool:
        return self.opkind.is_shifted_register

    @property
    def is_register_list(self) -> bool:
        return self.opkind.is_register_list

    @property
    def registers(self) -> List[str]:
        return self.opkind.registers

    @property
    def offset(self) -> int:
        return self.opkind.offset

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return self.opkind.ast_lvalue(astree)

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return self.opkind.ast_rvalue(astree)

    def __str__(self) -> str:
        return str(self.opkind)
