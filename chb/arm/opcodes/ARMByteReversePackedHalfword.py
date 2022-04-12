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
from chb.app.ASTNode import ASTInstruction

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("REV16", ARMOpcode)
class ARMByteReversePackedHalfword(ARMOpcode):
    """Reverses the byte order in each 16-bit halfword of a 32-bit register.

    REV16<c> <Rd>, <Rm>

    tags[1]: <c>
    args[0]: index of Rd in armdictionary
    args[1]: index of Rm in armdictionary
    args[2]: Thumb.wide
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "ByteReversePackedHalfword")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[:-1]]

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxx .

        vars[0]: lhs
        xprs[0]: rhs (original rhs)
        xprs[1]: rhs (original rhs, simplified)
        """

        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[1])
        return lhs + " := byte-reverse_halfwords(" + str(rhs) + ")"


    # --------------------------------------------------------------------------
    # Operation
    #   bits(32) result;
    #   result<31:24> = R[m]<23:16>;
    #   result<23:16> = R[m]<31:24>;
    #   result<15:8> = R[m]<7:0>
    #   result<7:0> = R[m]<15:8>
    #   R[d] = result;
    # --------------------------------------------------------------------------
    def assembly_ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[ASTInstruction]:

        annotations: List[str] = [iaddr, "REV16"]

        (rhs, _, _) = self.operands[1].ast_rvalue(astree)
        (lhs, _, _) = self.operands[0].ast_lvalue(astree)
        b0 = astree.mk_byte_expr(1, rhs)
        b1 = astree.mk_byte_expr(0, rhs)
        b2 = astree.mk_byte_expr(3, rhs)
        b3 = astree.mk_byte_expr(2, rhs)
        result = astree.mk_byte_sum([b0, b1, b2, b3])
        assign = astree.mk_assign(lhs, result, annotations=annotations)
        astree.add_instruction_span(assign.id, iaddr, bytestring)
        return [assign]
