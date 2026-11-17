# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023-2026  Aarno Labs LLC
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

from typing import List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger, CHKLogID

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMTableBranchHalfwordXData(ARMOpcodeXData):
    """Data format:
    - expressions:
    0: xrm  (index register)
    1: xxrm (index register rewritten)
    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def xrm(self) -> "XXpr":
        return self.xpr(0, "xrm")

    @property
    def xxrm(self) -> "XXpr":
        return self.xpr(1, "xxrm")

    @property
    def annotation(self) -> str:
        return f"branch on {self.xxrm}"


@armregistry.register_tag("TBH", ARMOpcode)
class ARMTableBranchHalfword(ARMOpcode):
    """PC-relative forward branching

    TBH<c> [<Rn>, <Rm>, LSL 1]

    tags[1]: <c>
    args[0]: index of base register operand
    args[1]: index of index register operand
    args[2]: index of memory operand
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "TableBranchHalfword")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [2]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1, 2]]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMTableBranchHalfwordXData(xdata)
        if xd.is_ok:
            return xd.annotation
        else:
            return "Error value"

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "TBH"]

        # low-level assignment

        (ll_rhs, _, _) = self.opargs[1].ast_rvalue(astree)
        ll_assign = astree.mk_assign(
            astree.ignoredlhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignment

        rdefs = xdata.reachingdefs
        xd = ARMTableBranchHalfwordXData(xdata)

        if xd.is_ok:
            rhs = xd.xxrm
        else:
            rhs = xd.xrm

        hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)

        hl_assign = astree.mk_assign(
            astree.ignoredlhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[0]])
        astree.add_expr_reachingdefs(hl_rhs, rdefs[1:])

        return ([hl_assign], [ll_assign])
