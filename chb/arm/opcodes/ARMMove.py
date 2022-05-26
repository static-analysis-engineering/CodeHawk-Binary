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


@armregistry.register_tag("MOV", ARMOpcode)
@armregistry.register_tag("MOVW", ARMOpcode)
class ARMMove(ARMOpcode):
    """Moves a constant or copies a register value to a destination register.

    MOV{S}<c> <Rd>, <Rm>

    tags[1]: <c>
    args[0]: {S}
    args[1]: index of op1 in armdictionary
    args[2]: index of op2 in armdictionary
    args[3]: is-wide (thumb)
    args[4]: wide
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "Move")

    @property
    def mnemonic(self) -> str:
        return self.tags[0] + ("W" if self.args[3] == 1 else "")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1: -2]]

    @property
    def operandstring(self) -> str:
        return ", ".join(str(op) for op in self.operands)

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vx . with optional condition, identified by
        tags[1]: "TC"

        vars[0]: lhs
        xprs[0]: rhs
        xprs[1]: condition (if flagged by tags[1])
        """

        if xdata.instruction_is_subsumed():
            return "subsumed by ITE"

        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[0])
        assignment = lhs + " := " + rhs
        if xdata.has_unknown_instruction_condition():
            return "if ? then " + assignment
        elif xdata.has_instruction_condition():
            c = str(xdata.xprs[1])
            return "if " + c + " then " + assignment
        else:
            return assignment

    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        if xdata.instruction_is_subsumed():
            return []
        else:
            annotations: List[str] = [iaddr, "MOV"]
            (lhs, _, _) = self.operands[0].ast_lvalue(astree)
            (rhs, _, _) = self.operands[1].ast_rvalue(astree)
            assign = astree.mk_assign(lhs, rhs, annotations=annotations)
            astree.add_instruction_span(assign.assembly_xref, iaddr, bytestring)
            return [assign]

    def ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        if xdata.instruction_is_subsumed():
            return []
        else:
            annotations: List[str] = [iaddr, "MOV"]
            lhss = XU.xvariable_to_ast_lvals(xdata.vars[0], astree)
            rhss = XU.xxpr_to_ast_exprs(xdata.xprs[0], astree)
            if len(lhss) == 1 and len(rhss) == 1:
                lhs = lhss[0]
                rhs = rhss[0]
                assign = astree.mk_assign(lhs, rhs, annotations=annotations)
                astree.add_instruction_span(assign.assembly_xref, iaddr, bytestring)
                return [assign]
            else:
                raise UF.CHBError(
                    "ARMMove: multiple expressions/lvals in ast")
