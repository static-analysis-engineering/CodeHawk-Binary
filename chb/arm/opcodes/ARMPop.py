# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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


@armregistry.register_tag("POP", ARMOpcode)
class ARMPop(ARMOpcode):
    """Loads multiple registers from the stack, and updates the stackpointer.

    POP<c> <registers>

    tags[1]: <c>
    args[0]: index of stackpointer operand in armdictionary
    args[1]: index of register list in armdictionary
    args[2]: is-wide (thumb)
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "Pop")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[:-1]]

    @property
    def operandstring(self) -> str:
        return str(self.operands[1])

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:v...x... .

        vars[0..n-1]: lhs variables
        xprs[0..n-1]: rhs memory values
        xprs[n]: conditional expression if TC is set
        """

        vars = xdata.vars
        xprs = xdata.xprs

        xctr = len(vars)
        pairs = zip(vars, xprs[:xctr])
        assigns = "; ".join(str(v) + " := " + str(x) for (v, x) in pairs)

        if xdata.has_instruction_condition():
            pcond = "if " + str(xprs[xctr]) + " then "
            xctr += 1
        elif xdata.has_unknown_instruction_condition():
            pcond = "if ? then "
        else:
            pcond = ""

        return pcond + assigns

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
        sp_incr = 4 * len(registers)
        sp_offset = 0
        for r in registers:
            sp_offset_c = astree.mk_integer_constant(sp_offset)
            addr = astree.mk_binary_op("plus", sprval, sp_offset_c)
            lhs = astree.mk_variable_lval(r)
            rhs = astree.mk_memref_expr(addr)
            instrs.append(astree.mk_assign(lhs, rhs))
            sp_offset += 4
        sp_incr_c = astree.mk_integer_constant(sp_incr)
        sp_rhs = astree.mk_binary_op("plus", sprval, sp_incr_c)
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
        instrs: List[AST.ASTInstruction] = []
        return []

        '''
        for (v, x) in zip(vars, xprs):
            lhs = astree.mk_variable_lval(str(v), str(v))
            rhs = astree.mk_variable_expr(str(x), str(x))
            instrs.append(astree.mk_assign(lhs, rhs))
        astree.add_instruction_span(instrs[0].id, iaddr, len(bytestring) // 2)
        return instrs
        '''
