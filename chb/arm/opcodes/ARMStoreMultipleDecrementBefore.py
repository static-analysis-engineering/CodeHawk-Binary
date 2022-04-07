# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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

from typing import List, TYPE_CHECKING

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree

import chb.app.ASTNode as AST

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("STMDB", ARMOpcode)
class ARMStoreMultipleDecrementBefore(ARMOpcode):
    """Stores multiple registers to consecutive memory locations.

    STMDB<c> <Rn>, <registers>

    tags[1]: <c>
    args[0]: writeback
    args[1]: index of Rn in arm dictionary
    args[2]: index of registers in arm dictionary
    args[3]: index of base memory address
    args[4]: thumb-wide
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "StoreMultipleDecrementBefore")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:-1]]

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxx .

        vars[0..n-1]: lhs expressions
        xprs[0..n-1]: rhs expressions
        xprs[n]: initial value of base register
        """

        return (
            "; ".join(
                str(v)
                + " := "
                + str(x) for (v,x) in zip(xdata.vars, xdata.xprs[:-1])))

    def assembly_ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        baseop = self.operands[0]
        regsop = self.operands[1]
        if not regsop.is_register_list:
            raise UF.CHBError("Argument to STMDB is not a register list")

        (reglval, _, _) = baseop.ast_lvalue(astree)
        (regrval, _, _) = baseop.ast_rvalue(astree)

        instrs: List[AST.ASTInstruction] = []
        registers = regsop.registers
        reg_decr = 4 * len(registers)
        reg_offset = reg_decr
        for r in registers:
            reg_offset_c = astree.mk_integer_constant(reg_offset)
            addr = astree.mk_binary_op("minus", regrval, reg_offset_c)
            lhs = astree.mk_memref_lval(addr)
            rhs = astree.mk_register_variable_expr(r)
            instrs.append(astree.mk_assign(lhs, rhs))
            reg_offset -= 4
        if self.args[0] == 1:
            reg_decr_c = astree.mk_integer_constant(reg_decr)
            reg_rhs = astree.mk_binary_op("minus", regrval, reg_decr_c)
            instrs.append(astree.mk_assign(reglval, reg_rhs))
        astree.add_instruction_span(instrs[0].id, iaddr, bytestring)
        return instrs

    def ast(self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        vars = xdata.vars
        xprs = xdata.xprs[:-1]
        basexpr = xdata.xprs[-1]

        instrs: List[AST.ASTInstruction] = []

        rhss = XU.xxpr_list_to_ast_exprs(xprs, astree)

        for (v, x) in zip(vars, xprs):
            lhs = XU.xvariable_to_ast_lval(v, astree)
            rhs = XU.xxpr_to_ast_expr(x, astree)
            instrs.append(astree.mk_assign(lhs, rhs))

        astree.add_instruction_span(instrs[0].id, iaddr, bytestring)
        return instrs
