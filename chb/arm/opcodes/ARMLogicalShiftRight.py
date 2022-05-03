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
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("LSR", ARMOpcode)
class ARMLogicalShiftRight(ARMOpcode):
    """Shifts a register value right by an immediate value, or value in a register.

    LSR{S}<c> <Rd>, <Rn>, <Rm>

    tags[1]: <c>
    args[0]: {S}
    args[1]: index of Rd in armdictionary
    args[2]: index of Rn in armdictionary
    args[3]: index of Rm in armdictionary
    args[4]: is-wide (thumb)
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:-1]]

    @property
    def mnemonic(self) -> str:
        mnem = self.tags[0]
        if self.is_writeback:
            return mnem + "S"
        else:
            return mnem

    @property
    def is_writeback(self) -> bool:
        return self.args[0] == 1

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxxx .

        vars[0]: lhs
        xprs[0]: rhs1
        xprs[1]: rhs2
        xprs[2]: rhs1 >> rhs2 (syntactic)
        xprs[3]: rhs1 >> rhs2 (simplified)
        """

        lhs = str(xdata.vars[0])
        result = xdata.xprs[1]
        rresult = xdata.xprs[2]
        xresult = simplify_result(xdata.args[2], xdata.args[3], result, rresult)
        return lhs + " := " + xresult

    def assembly_ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:

        annotations: List[str] = [iaddr, "LSR"]

        (rhs1, preinstrs1, postinstrs1) = self.operands[1].ast_rvalue(astree)
        (rhs2, preinstrs2, postinstrs2) = self.operands[2].ast_rvalue(astree)
        (lhs, _, _) = self.operands[0].ast_lvalue(astree)
        binop = astree.mk_binary_op("lsr", rhs1, rhs2)
        assign = astree.mk_assign(lhs, binop, annotations=annotations)
        astree.add_instruction_span(assign.instrid, iaddr, bytestring)
        return preinstrs1 + preinstrs2 + [assign] + postinstrs1 + postinstrs2
