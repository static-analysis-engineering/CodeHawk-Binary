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

from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree
import chb.ast.ASTNode as AST

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.arm.ARMDictionary


@armregistry.register_tag("UXTB", ARMOpcode)
class ARMUnsignedExtendByte(ARMOpcode):
    """Extracts an 8-bit value from a register, zero-extends it.

    UXTB<c> <Rd>, <Rm>{, <rotation>}

    tags[1]: <c>
    args[0]: index of op1 in armdictionary
    args[1]: index of op2 in armdictionary
    args[2]: thumb wide
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "UnsignedExtendByte")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[:-1]]

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxxx .

        vars[0]: lhs
        xprs[0]: rhs1
        xprs[1]: value to be stored (syntactic)
        xprs[2]: value to be stored (simplified)
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

        annotations: List[str] = [iaddr, "UXTB"]

        (rhs, preinstrs, postinstrs) = self.operands[1].ast_rvalue(astree)
        (lhs, _, _) = self.operands[0].ast_lvalue(astree)
        rhss = XU.xxpr_to_ast_exprs(xdata.xprs[2], astree)
        if len(rhss) == 1:
            rhs = rhss[0]
            mask = astree.mk_integer_constant(255)
            rhs = astree.mk_binary_op("band", rhs, mask)
            annotations.append("mask except first byte")
        elif len(rhss) == 4:
            annotations.append("select first byte")
            rhs = rhss[0]
        else:
            raise UF.CHBError(
                "UXTB: Received "
                + str(len(rhss))
                + " expressions: "
                + ", ".join((str(rhs) for rhs in rhss)))

        assign = astree.mk_assign(lhs, rhs, annotations=annotations)
        astree.add_instruction_span(assign.instrid, iaddr, bytestring)
        return preinstrs + [assign] + postinstrs
