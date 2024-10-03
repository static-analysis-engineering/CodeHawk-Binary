# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024 Aarno Labs LLC
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

from typing import List, Optional, Sequence, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMCallOpcode import ARMCallOpcode
from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XXpr

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget, AppTarget, StaticStubTarget
    import chb.arm.ARMDictionary


@armregistry.register_tag("BX", ARMOpcode)
class ARMBranchExchange(ARMCallOpcode):
    """Branch to an address and instruction set specified by a register.

    tags[1]: <c>
    args[0]: index of target operand in armdictionary
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 1, "BranchExchange")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    def ft_conditions(self, xdata: InstrXData) -> Sequence[XXpr]:
        if xdata.has_branch_conditions():
            return [xdata.xprs[1], xdata.xprs[0]]
        else:
            return []

    def is_return_instruction(self, xdata: InstrXData) -> bool:
        tgtop = self.operands[0]
        if tgtop.is_register:
            return tgtop.register == "LR"
        else:
            return False

    def return_value(self, xdata: InstrXData) -> Optional[XXpr]:
        if self.is_return_instruction(xdata):
            return xdata.xprs[1]
        else:
            return None

    def is_call(self, xdata: InstrXData) -> bool:
        return len(xdata.tags) >= 2 and xdata.tags[1] == "call"

    def is_call_instruction(self, xdata: InstrXData) -> bool:
        return xdata.has_call_target()

    def call_target(self, xdata: InstrXData) -> "CallTarget":
        if self.is_call_instruction(xdata):
            return xdata.call_target(self.ixd)
        else:
            raise UF.CHBError("Instruction is not a call: " + str(self))

    def arguments(self, xdata: InstrXData) -> Sequence[XXpr]:
        return xdata.xprs

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:x .

        xprs[0]: target operand
        """
        if self.is_call_instruction(xdata):
            tgt = xdata.call_target(self.ixd)
            args = ", ".join(str(x) for x in self.arguments(xdata))
            return "call " + str(tgt) + "(" + args + ")"

        tgtop = str(xdata.xprs[0])
        if tgtop == "LR":
            return "return"
        else:
            return "goto " + tgtop

    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        """Need check for branch on LR, which should emit a return statement."""
        return []

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "BX"]

        if self.is_call_instruction(xdata) and xdata.has_call_target():
            return self.ast_call_prov(
                astree, iaddr, bytestring, "BranchExchange", xdata)
        else:
            nopinstr = astree.mk_nop_instruction(
                "BX", iaddr=iaddr, bytestring=bytestring, annotations=annotations)
            astree.add_instr_address(nopinstr, [iaddr])

            return ([], [nopinstr])

    def ast_call_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            name: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        return ARMCallOpcode.ast_call_prov(
            self, astree, iaddr, bytestring, "BranchExchange (BX)", xdata)
