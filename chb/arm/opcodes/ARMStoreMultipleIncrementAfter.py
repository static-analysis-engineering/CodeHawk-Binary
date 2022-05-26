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

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("STM", ARMOpcode)
class ARMStoreMultipleIncrementAfter(ARMOpcode):
    """Stores multiple registers to consecutive memory locations.

    STM<c> <Rn>, <registers>

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
        self.check_key(2, 5, "StoreMultipleIncrementAfter")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:-1]]

    @property
    def operandstring(self) -> str:
        return (
            str(self.armd.arm_operand(self.args[1]))
            + ("!" if self.args[0] == 1 else "")
            + ", "
            + str(self.armd.arm_operand(self.args[2])))

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxx .

        vars[0..n]: lhs variables
        xprs[0..n]: rhs expressions
        """

        return '; '.join(
            str(lhs) + " := " + str(x) for (lhs, x) in zip(xdata.vars, xdata.xprs))

    # --------------------------------------------------------------------------
    # address = R[n];
    # for i = 0 to 14
    #   if registers<i> == '1' then
    #     MemA[address, 4] = R[i];
    #     address = address + 4;
    # if registers<15> == '1' then
    #   MemA[address, 4] = PCStoreValue();
    # if wback then
    #   R[n] = R[n] + 4 * BitCount(registers);
    # --------------------------------------------------------------------------
    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        baseop = self.operands[0]
        regsop = self.operands[1]
        if not regsop.is_register_list:
            raise UF.CHBError("Argument to STM is not a register list")

        (reglval, _, _) = baseop.ast_lvalue(astree)
        (regrval, _, _) = baseop.ast_rvalue(astree)

        instrs: List[AST.ASTInstruction] = []
        registers = regsop.registers
        reg_incr = 4 * len(registers)
        reg_offset = 0
        for r in registers:
            reg_offset_c = astree.mk_integer_constant(reg_offset)
            addr = astree.mk_binary_op("plus", regrval, reg_offset_c)
            lhs = astree.mk_memref_lval(addr)
            rhs = astree.mk_register_variable_expr(r)
            instrs.append(astree.mk_assign(lhs, rhs))
            reg_offset += 4
        if self.args[0] == 1:
            reg_incr_c = astree.mk_integer_constant(reg_incr)
            reg_rhs = astree.mk_binary_op("plus", regrval, reg_incr_c)
            instrs.append(astree.mk_assign(reglval, reg_rhs))

        for instr in instrs:
            astree.add_instruction_span(instr.assembly_xref, iaddr, bytestring)
        return instrs

    def ast(self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        vars = xdata.vars
        xprs = xdata.xprs[:-1]
        basexpr = xdata.xprs[-1]

        instrs: List[AST.ASTInstruction] = []

        for (v, x) in zip(vars, xprs):
            lhss = XU.xvariable_to_ast_lvals(v, astree)
            rhss = XU.xxpr_to_ast_exprs(x, astree)
            if len(lhss) == 1 and len(rhss) == 1:
                lhs = lhss[0]
                rhs = rhss[0]
                instrs.append(astree.mk_assign(lhs, rhs))
            else:
                raise UF.CHBError(
                    "ARMStoreMulipleIncrementAfter: multiple expressions/lvals in ast")

        for instr in instrs:
            astree.add_instruction_span(instr.assembly_xref, iaddr, bytestring)
        return instrs
