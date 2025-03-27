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

from typing import cast, List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XXpr import XXpr


class ARMCompareXData(ARMOpcodeXData):
    """Data format:
    ---------------
    - expressions:
    0: xrn
    1: xrm:
    2: xresult (xrn - xrm)
    3: result (xresult rewritten)

    - c expressions:
    0: cresult

    rdefs[0]: rn
    rdefs[1]: rm
    rdefs[2..]: xrn - xrm (simplified)
    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def xrn(self) -> "XXpr":
        return self.xpr(0, "xrn")

    @property
    def xrm(self) -> "XXpr":
        return self.xpr(1, "xrm")

    @property
    def xresult(self) -> "XXpr":
        return self.xpr(2, "xresult")

    @property
    def result(self) -> "XXpr":
        return self.xpr(3, "result")

    @property
    def is_result_ok(self) -> bool:
        return self.is_xpr_ok(3)

    @property
    def cresult(self) -> "XXpr":
        return self.cxpr(0, "cresult")

    @property
    def is_cresult_ok(self) -> bool:
        return self.is_cxpr_ok(0)

    @property
    def annotation(self) -> str:
        cx = " (C: " + (str(self.cresult) if self.is_cresult_ok else "None") + ")"
        ann = "compare " + str(self.xrn) + " and " + str(self.xrm)
        if self.is_ok:
            ann += " (" + str(self.result) + ")" + cx
        return self.add_instruction_condition(ann)


@armregistry.register_tag("CMP", ARMOpcode)
class ARMCompare(ARMOpcode):
    """Subtracts a register or imm. value from a register value and sets flags.

    CMP<c> <Rn>, #<imm8>
    CMP<c>.W <Rn>, #<const>
    CMP<c> <Rn>, #<const>
    CMP<c> <Rn>, <Rm>
    CMP<c>.W <Rn>, <Rm> {, <shift>}
    CMP<c> <Rn>, <Rm>, <type> <Rs>

    tags[1]: <c>
    args[0]: index of rn in armdictionary
    args[1]: index of rm in armdictionary
    args[2]: is-wide (thumb)
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "Compare")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[2] == 1 else ""
        return cc + wide

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[:-1]]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMCompareXData(xdata)
        return xd.annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        """Creates assignments of the subtraction performed with lhs ignored."""

        annotations: List[str] = [iaddr, "CMP"]

        # low-level assignment

        (ll_rhs1, _, _) = self.opargs[0].ast_rvalue(astree)
        (ll_rhs2, _, _) = self.opargs[1].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("minus", ll_rhs1, ll_rhs2)

        ll_assign = astree.mk_assign(
            astree.ignoredlhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignment

        rdefs = xdata.reachingdefs
        xd = ARMCompareXData(xdata)

        if xd.is_cresult_ok:
            rhs = xd.cresult
        elif xd.is_result_ok:
            rhs = xd.result
        else:
            rhs = xd.xresult

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
        astree.add_expr_reachingdefs(ll_rhs1, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_rhs2, [rdefs[1]])
        astree.add_expr_reachingdefs(hl_rhs, rdefs[2:])

        return ([hl_assign], [ll_assign])
