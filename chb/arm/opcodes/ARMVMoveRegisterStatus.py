# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2025  Aarno Labs LLC
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

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMVMoveRegisterStatusXData(ARMOpcodeXData):
    """
    Data format:
    - variables
    0: vdst_r

    - expressions
    0: xsrc_r
    """

    def __init__(self, xdata: InstrXData):
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vdst(self) -> "XVariable":
        return self.var(0, "vdst")

    @property
    def xsrc(self) -> "XXpr":
        return self.xpr(0, "xsrc")

    @property
    def annotation(self) -> str:
        return str(self.vdst) + " := " + str(self.xsrc)


@armregistry.register_tag("VMRS", ARMOpcode)
class ARMVMoveRegisterStatus(ARMOpcode):
    """Move floating-point status word to core register (or processor status word)

    VMRS<c> <Rt> FPSCR

    tags[1]: <c>
    args[0]: index of destination register in armdictionary
    args[1]: index of source in armdictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 2, "VMoveRegisterStatus")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1]]

    def annotation(self, xdata: InstrXData) -> str:
        return str(self.operands[0]) + " := FPSCR"

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VMRS"]

        xd = ARMVMoveRegisterStatusXData(xdata)

        lhs = xd.vdst
        rhs = xd.xsrc
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        (ll_rhs, _, _) = self.opargs[1].ast_rvalue(astree)
        ll_assign = astree.mk_assign(
            astree.ignoredlhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        hl_rhs = ll_rhs
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
