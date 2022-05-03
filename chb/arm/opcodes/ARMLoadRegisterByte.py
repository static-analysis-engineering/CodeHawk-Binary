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

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.arm.ARMDictionary


@armregistry.register_tag("LDRB", ARMOpcode)
class ARMLoadRegisterByte(ARMOpcode):
    """Loads a byte from memory, zero-extends it to 32 bits, and writes it to a register.

    LDRB<c> <Rt>, [<base>, <offset>]

    tags[0]: <c>
    args[0]: index of destination operand in armdictionary
    args[1]: index of base register in armdictionary
    args[2]: index of index in armdictionary
    args[3]: index of memory location in armdictionary
    args[4]: is-wide (thumb)
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "LoadRegisterByte")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 3]]

    def is_load_instruction(self, xdata: InstrXData) -> bool:
        return True

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return [xdata.xprs[1]]

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxx .

        vars[0]: lhs
        vars[1]: memory location expressed as a variable
        xprs[0]: value in memory location
        xprs[1]: value in memory location (simplified)
        """

        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[1])
        return lhs + " := " + rhs

    def assembly_ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:

        annotations: List[str] = [iaddr, "LDRB"]

        (rhs, preinstrs, postinstrs) = self.operands[1].ast_rvalue(astree)
        (lhs, _, _) = self.operands[0].ast_lvalue(astree)
        assign = astree.mk_assign(lhs, rhs, annotations=annotations)
        astree.add_instruction_span(assign.instrid, iaddr, bytestring)
        return preinstrs + [assign] + postinstrs

    def ast(self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:

        annotations: List[str] = [iaddr, "LDR"]

        preinstrs: List[AST.ASTInstruction] = []
        postinstrs: List[AST.ASTInstruction] = []
        rhsrvals = XU.xxpr_to_ast_exprs(xdata.xprs[1], astree)
        lhss = XU.xvariable_to_ast_lvals(xdata.vars[0], astree)        
        if len(rhsrvals) == 1 and len(lhss) == 1:
            rhsrval = rhsrvals[0]
            lhs = lhss[0]
            if str(rhsrval).startswith("temp") or str(rhsrval).startswith("(temp"):
                (rhsrval, preinstrs, postinstrs) = self.operands[1].ast_rvalue(astree)

            assign = astree.mk_assign(lhs, rhsrval, annotations=annotations)
            astree.add_instruction_span(assign.instrid, iaddr, bytestring)
            return preinstrs + [assign] + postinstrs
        else:
            raise UF.CHBError(
                "ARMLoadRegisterByte: multiple expressions/lvals in ast")
