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

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("IT", ARMOpcode)
class ARMIfThen(ARMOpcode):
    """Makes up to four following instructions conditional.

    The conditions for the instructions in the IT block are the same as, or the
    inverse of, the condition of the IT instruction specified for the first
    instruction in the block..

    IT{<x>{<y>{<z>}}} <firstcond>

    tags[1]: <c>
    tags[2]: xyz
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)

    @property
    def operands(self) -> List[ARMOperand]:
        return []

    def annotation(self, xdata: InstrXData) -> str:
        if len(xdata.vars) == 1 and len(xdata.xprs) == 1:
            lhs = str(xdata.vars[0])
            rhs = str(xdata.xprs[0])
            return lhs + " := " + rhs
        else:
            return self.tags[0]

    def assembly_ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        if len(xdata.vars) == 1 and len(xdata.xprs) == 1:
            lhs = astree.mk_variable_lval(str(xdata.vars[0]))
            rhss = XU.xxpr_to_ast_exprs(xdata.xprs[0], astree)
            if len(rhss) == 1:
                rhs = rhss[0]
                assign = astree.mk_assign(lhs, rhs)
                astree.add_instruction_span(assign.instrid, iaddr, bytestring)
                return [assign]
            else:
                return []
        else:
            raise UF.CHBError(
                "ARMIfThen: multiple expressions/lvals in ast")
