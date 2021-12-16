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

from typing import cast, List, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree
from chb.app.ASTNode import ASTInstruction

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.arm.ARMDictionary
    from chb.invariants.XXpr import XprCompound


@armregistry.register_tag("ADD", ARMOpcode)
class ARMAdd(ARMOpcode):
    """Add (register, constant)

    ADD{S}<c> <Rd>, <Rn>, <Rm>{, <shift>} (arm)
    ADD{S}<c> <Rd>, <Rn>, #<const> (arm, thumb)
    ADD{S}<c>.W <Rd>, <Rn>, #<const> (thumb)
    ADD{S}<c> <Rdn>, #<const> (thumb)
    ADD<c> <Rdn>, <Rm> (thumb)
    ADD<c> SP, <Rm> (thumb)
    ADD<c> <Rd>, SP, #<const> (thumb)
    ADD<c> SP, SP, #<const> (thumb)
    ADD<c> <Rdm>, SP, <Rdm> (thumb)

    tags[1]: <c>
    args[0]: {S}
    args[1]: index of op1 in armdictionary
    args[2]: index of op2 in armdictionary
    args[3]: index of op3 in armdictionary
    args[4]: is-wide (thumb)
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "Add")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:-1]]

    @property
    def writeback(self) -> bool:
        return self.args[0] == 1

    def mnemonic_extension(self) -> str:
        wb = "S" if self.writeback else ""
        cc = ARMOpcode.mnemonic_extension(self)
        return wb + cc

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxxxx .

        vars[0]: lhs (Rd)
        xprs[0]: rhs1 (Rn)
        xprs[1]: rhs2 (Rm{..})
        xprs[2]: rhs1 + rhs2 (syntactic)
        xprs[3]: rhs1 + rhs2 (simplified)
        """

        lhs = str(xdata.vars[0])
        result = xdata.xprs[2]
        rresult = xdata.xprs[3]
        xresult = simplify_result(xdata.args[3], xdata.args[4], result, rresult)
        return lhs + " := " + xresult

    def assembly_ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[ASTInstruction]:
        (lhs, _, _) = self.operands[0].ast_lvalue(astree)
        (op1, _, _) = self.operands[1].ast_rvalue(astree)
        (op2, _, _) = self.operands[2].ast_rvalue(astree)
        binop = astree.mk_binary_op("plus", op1, op2)
        result = astree.mk_assign(lhs, binop)
        astree.add_instruction_span(result.id, iaddr, bytestring)
        return [result]

    def ast(self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[ASTInstruction]:
        lhs = str(xdata.vars[0])
        rhs1 = str(xdata.xprs[0])
        rhs2 = xdata.xprs[1]
        rhs3 = xdata.xprs[3]

        if lhs == "SP" and rhs1 == "SP" and rhs2.is_constant:
            return []

        if rhs1 == "SP" and rhs3.is_stack_address:
            print("Stack address: " + str(rhs3))
            rhs3 = cast("XprCompound", rhs3)
            stackoffset = rhs3.stack_address_offset()
            if stackoffset < 0:
                lhsast = astree.mk_variable_lval(lhs)
                stackoffset = -stackoffset
                varnum = "{0:0>4}".format(stackoffset)
                varname = "var." + varnum
                rhslval = astree.mk_variable_lval(varname)
                rhs = astree.mk_address_of(rhslval)
                result = astree.mk_assign(lhsast, rhs)
                astree.add_instruction_span(result.id, iaddr, bytestring)
                return [result]

        return self.assembly_ast(astree, iaddr, bytestring, xdata)
