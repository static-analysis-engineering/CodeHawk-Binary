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

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.arm.ARMDictionary


@armregistry.register_tag("PUSH", ARMOpcode)
class ARMPush(ARMOpcode):
    """Stores multiple registers to the stack, and updates the stackpointer.

    PUSH<c> <registers>

    tags[1]: <c>
    args[0]: index of stackpointer in armdictionary
    args[1]: index of register list
    args[2]: is-wide (thumb)
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "Push")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1]]

    @property
    def operandstring(self) -> str:
        return str(self.operands[1])

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:v...x...

        vars[0..n]: stack locations
        xprs[0..n]: register values
        """

        vars = xdata.vars
        xprs = xdata.xprs
        assigns = '; '.join(
            str(v) + " := " + str(x) for (v, x) in zip(vars, xprs))
        return assigns

    def assembly_ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        regsop = self.operands[1]
        if not regsop.is_register_list:
            raise UF.CHBError("Argument to push is not a register list")

        (splval, _, _) = self.operands[0].ast_lvalue(astree)
        (sprval, _, _) = self.operands[0].ast_rvalue(astree)

        instrs: List[AST.ASTInstruction] = []
        registers = regsop.registers
        sp_decr = 4 * len(registers)
        sp_offset = sp_decr
        for r in registers:
            sp_offset_c = astree.mk_integer_constant(sp_offset)
            addr = astree.mk_binary_op("minus", sprval, sp_offset_c)
            lhs = astree.mk_memref_lval(addr)
            rhs = astree.mk_register_variable_expr(r)
            instrs.append(astree.mk_assign(lhs, rhs))
            sp_offset -= 4
        sp_decr_c = astree.mk_integer_constant(sp_decr)
        sp_rhs = astree.mk_binary_op("minus", sprval, sp_decr_c)
        instrs.append(astree.mk_assign(splval, sp_rhs))
        astree.add_instruction_span(instrs[0].id, iaddr, bytestring)
        return instrs

    def ast(self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        vars = xdata.vars
        xprs = xdata.xprs
        return []

        '''
        instrs: List[AST.ASTInstruction] = []
        for (v, x) in zip(vars, xprs):
            lhs = astree.mk_variable_lval(str(v))
            rhs = astree.mk_variable_expr(str(x))
            instrs.append(astree.mk_assign(lhs, rhs))
        astree.add_instruction_span(instrs[0].id, iaddr, bytestring)
        return instrs
        '''
