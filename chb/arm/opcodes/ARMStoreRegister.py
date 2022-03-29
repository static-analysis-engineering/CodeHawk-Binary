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

from typing import cast, List, TYPE_CHECKING

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree

import chb.app.ASTNode as AST

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.VAssemblyVariable import VMemoryVariable


@armregistry.register_tag("STR", ARMOpcode)
class ARMStoreRegister(ARMOpcode):
    """Stores a word from a register into memory.

    STR<c> <Rt>, [<base>, <offset>]

    tags[1]: <c>
    args[0]: index of source operand in armdictionary
    args[1]: index of base register in armdictionary
    args[2]: index of memory location in armdictionary
    args[3]: is-wide (thumb)
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "StoreRegister")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 2]]

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxx .

        vars[0]: lhs
        xprs[0]: rhs
        xprs[1]: rhs (simplified)
        xprs[2]: condition (if TC is set)
        """

        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[1])
        if xdata.xprs[1].is_function_return_value:
            rhs = str(xdata.xprs[1].variable.denotation)
        assign = lhs + " := " + rhs

        xctr = 2
        if xdata.has_instruction_condition():
            pcond = "if " + str(xdata.xprs[xctr]) + " then "
            xctr += 1
        elif xdata.has_unknown_instruction_condition():
            pcond = "if ? then "
        else:
            pcond = ""

        return pcond + assign

    def assembly_ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        (lhs, preinstrs, postinstrs) = self.operands[1].ast_lvalue(astree)
        (rhs, _, _) = self.operands[0].ast_rvalue(astree)
        assign = astree.mk_assign(lhs, rhs)
        astree.add_instruction_span(assign.id, iaddr, bytestring)
        return preinstrs + [assign] + postinstrs

    def ast(self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        # (rhs, _, _) = self.operands[0].ast_rvalue(astree)
        rhs = XU.xxpr_to_ast_expr(xdata.xprs[1], astree)
        lhs = xdata.vars[0]
        if str(lhs).startswith("?"):
            return self.assembly_ast(astree, iaddr, bytestring, xdata)

        lval = XU.xvariable_to_ast_lval(lhs, astree)
        assign = astree.mk_assign(lval, rhs)
        astree.add_instruction_span(assign.id, iaddr, bytestring)
        return [assign]
