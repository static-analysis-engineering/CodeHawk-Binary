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


@armregistry.register_tag("MOVT", ARMOpcode)
class ARMMoveTop(ARMOpcode):
    """Writes an immediate value to the top halfword of the destination register.

    MOVT<c> <Rd>, #<imm16>

    tags[1]: <c>
    args[0]: index of Rd in arm dictionary
    args[1]: index of imm16 in arm dictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 2, "MoveTop")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args]

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vx .

        vars[0]: lhs (Rd)
        xprs[0]: imm16
        xprs[1]: rhs (Rd)
        xprs[2]: rhs % 2^16
        xprs[3]: (rhs % 2^16) + (2^16 * imm16) (syntactic)
        xprs[4]: (rhs % 2^16) + (2^16 * imm16) (simplified)
        """

        lhs = str(xdata.vars[0])
        result = xdata.xprs[3]
        rresult = xdata.xprs[4]
        xresult = simplify_result(xdata.args[4], xdata.args[5], result, rresult)
        return lhs + " := " + xresult

    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:

        annotations: List[str] = [iaddr, "MOVT"]

        (lhs, _, _) = self.operands[0].ast_lvalue(astree)
        (op1, _, _) = self.operands[1].ast_rvalue(astree)
        (op2, _, _) = self.operands[0].ast_rvalue(astree)
        i16 = astree.mk_integer_constant(16)
        e16 = astree.mk_integer_constant(256 * 256)
        xpr1 = astree.mk_binary_op("lsl", op2, i16)
        xpr2 = astree.mk_binary_op("mod", op1, e16)
        xpr = astree.mk_binary_op("plus", xpr1, xpr2)
        assign = astree.mk_assign(
            lhs, xpr, iaddr=iaddr, bytestring=bytestring, annotations=annotations)
        return [assign]

    def ast(self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:

        annotations: List[str] = [iaddr, "MOVT"]

        lhss = XU.xvariable_to_ast_lvals(xdata.vars[0], astree)
        rhss = XU.xxpr_to_ast_exprs(xdata.xprs[4], astree)
        if len(lhss) == 1 and len(rhss) == 1:
            lhs = lhss[0]
            rhs = rhss[0]
            assign = astree.mk_assign(
                lhs,
                rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            return [assign]
        else:
            raise UF.CHBError(
                "ARMMoveTop: multiple expressions/lvals in ast")
