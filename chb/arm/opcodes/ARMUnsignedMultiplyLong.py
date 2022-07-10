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

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("UMULL", ARMOpcode)
class ARMUnsignedMultiplyLong(ARMOpcode):
    """Multiplies two unsigned 32-bit signed values to produce a 64-bit result

    UMULL{S}<c> <RdLo>, <RdHi>, <Rn>, <Rm>

    tags[1]: <c>
    args[0]: flags are set
    args[1]: index of RdLo in armdictionary
    args[2]: index of RdHi in armdictionary
    args[3]: index of Rn in armdictionary
    args[4]: index of Rm in armdictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "UnsignedMultiplyLong")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:]]

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxxxx

        vars[0]: lhslo
        vars[1]: lhshi
        xprs[0]: rhs1
        xprs[1]: rhs2
        xprs[2]: (rhs1 * rhs2)
        xprs[3]: (rhs1 * rhs2)
        """

        lhslo = str(xdata.vars[0])
        lhshi = str(xdata.vars[1])
        result = xdata.xprs[2]
        rresult = xdata.xprs[3]
        xresult = simplify_result(xdata.args[4], xdata.args[5], result, rresult)
        return "(" + lhslo + "," + lhshi + ")" + " := " + xresult

    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:

        annotations: List[str] = [iaddr, "UMULL"]

        (rhs1, preinstrs1, postinstrs1) = self.operands[2].ast_rvalue(astree)
        (rhs2, preinstrs2, postinstrs2) = self.operands[3].ast_rvalue(astree)
        (lhs1, _, _) = self.operands[0].ast_lvalue(astree)
        (lhs2, _, _) = self.operands[1].ast_lvalue(astree)
        binop = astree.mk_binary_op("mult", rhs1, rhs2)
        zero = astree.mk_integer_constant(0)
        assign1 = astree.mk_assign(
            lhs1,
            binop,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=(annotations + ["low"]))
        assign2 = astree.mk_assign(
            lhs2,
            zero,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)
        return preinstrs1 + preinstrs2 + [assign1, assign2] + postinstrs1 + postinstrs2
