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


@armregistry.register_tag("STRD", ARMOpcode)
class ARMStoreRegisterDual(ARMOpcode):
    """Stores words from two registers into memory.

    STRD<c> <Rt>, <Rt2>, [<Rn>,+/-<Rm>]{!}

    tags[1]: <c>
    args[0]: index of first destination operand in armdictionary
    args[1]: index of second destination operand in armdictionary
    args[2]: index of base register in armdictionary
    args[3]: index of index register / immediate in armdictionary
    args[4]: index of memory location in armdictionary
    args[5]: index of second memory location in armdictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 6, "StoreRegisterDual")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1, 4, 5]]

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vvxxxx .

        vars[0]: lhs1
        vars[1]: lhs2
        xprs[0]: value in first register
        xprs[1]: value in first register (simplified)
        xprs[2]: value in second register
        xprs[3]: value in second register (simplified)
        """

        lhs1 = str(xdata.vars[0])
        lhs2 = str(xdata.vars[1])
        rhs = str(xdata.xprs[1])
        rhs2 = str(xdata.xprs[3])
        return lhs1 + " := " + rhs + "; " + lhs2 + " := " + rhs2

    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        (lhs1, preinstrs1, postinstrs1) = self.operands[2].ast_lvalue(astree)
        (lhs2, preinstrs2, postinstrs2) = self.operands[3].ast_lvalue(astree)
        (rhs1, _, _) = self.operands[0].ast_rvalue(astree)
        (rhs2, _, _) = self.operands[1].ast_rvalue(astree)
        assign1 = astree.mk_assign(lhs1, rhs1, iaddr=iaddr, bytestring=bytestring)
        assign2 = astree.mk_assign(lhs2, rhs2, iaddr=iaddr, bytestring=bytestring)
        return (
            preinstrs1
            + preinstrs2
            + [assign1, assign2]
            + postinstrs1
            + postinstrs2)

    def ast(self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        (rhs1, _, _) = self.operands[0].ast_rvalue(astree)
        (rhs2, _, _) = self.operands[1].ast_rvalue(astree)
        lhs1 = str(xdata.vars[0])
        lhs2 = str(xdata.vars[1])
        if lhs1.endswith("[0]"):
            lhs1 = "*" + lhs1[:-3]
        lval1 = astree.mk_variable_lval(lhs1)
        lval2 = astree.mk_variable_lval(lhs2)
        assign1 = astree.mk_assign(lval1, rhs1, iaddr=iaddr, bytestring=bytestring)
        assign2 = astree.mk_assign(lval2, rhs2, iaddr=iaddr, bytestring=bytestring)
        return [assign1, assign2]
