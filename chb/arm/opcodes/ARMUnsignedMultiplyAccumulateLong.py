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
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMUnsignedMultiplyAccumulateLongXData(ARMOpcodeXData):

    @property
    def vlo(self) -> "XVariable":
        return self.var(0, "vlo")

    @property
    def vhi(self) -> "XVariable":
        return self.var(1, "vhi")

    @property
    def xrn(self) -> "XXpr":
        return self.xpr(0, "xrn")

    @property
    def xrm(self) -> "XXpr":
        return self.xpr(1, "xrm")

    @property
    def xlo(self) -> "XXpr":
        return self.xpr(2, "xlo")

    @property
    def xhi(self) -> "XXpr":
        return self.xpr(3, "xhi")

    @property
    def result(self) -> "XXpr":
        return self.xpr(4, "result")

    @property
    def rresult(self) -> "XXpr":
        return self.xpr(5, "rresult")

    @property
    def result_simplified(self) -> str:
        return simplify_result(
            self.xdata.args[6], self.xdata.args[7], self.result, self.rresult)

    @property
    def annotation(self) -> str:
        assignment = str(self.vlo) + " := " + self.result_simplified
        return self.add_instruction_condition(assignment)


@armregistry.register_tag("UMLAL", ARMOpcode)
class ARMUnsignedMultiplyAccumulateLong(ARMOpcode):
    """Multiplies two unsigned 32-bit signed values and accumulates in a 64-bit result

    UMLAL{S}<c> <RdLo>, <RdHi>, <Rn>, <Rm>

    tags[1]: <c>
    args[0]: flags are set
    args[1]: index of RdLo in armdictionary
    args[2]: index of RdHi in armdictionary
    args[3]: index of Rn in armdictionary
    args[4]: index of Rm in armdictionary
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "UnsignedMultiplyAccumulateLong")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3, 4]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3, 4]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wb = "S" if self.is_writeback else ""
        return wb + cc

    @property
    def is_writeback(self) -> bool:
        return self.args[0] == 1

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMUnsignedMultiplyAccumulateLongXData(xdata)
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

        annotations: List[str] = [iaddr, "UMLAL"]

        # low-level assignment

        (ll_lhslo, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_lhshi, _, _) = self.opargs[1].ast_lvalue(astree)
        (ll_lo, _, _) = self.opargs[0].ast_rvalue(astree)
        (ll_hi, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_rn, _, _) = self.opargs[2].ast_rvalue(astree)
        (ll_rm, _, _) = self.opargs[3].ast_rvalue(astree)

        i32 = astree.mk_integer_constant(32)
        ll_rhs1 = astree.mk_doubleword_sum(ll_hi, ll_lo)
        ll_rhs2 = astree.mk_binary_op("mult", ll_rn, ll_rm)
        ll_rhs = astree.mk_binary_op("plus", ll_rhs2, ll_rhs1)
        ll_rhslo = astree.mk_binary_op("mod", ll_rhs, i32)
        ll_rhshi = astree.mk_binary_op("div", ll_rhs, i32)

        ll_assign_lo = astree.mk_assign(
            ll_lhslo,
            ll_rhslo,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        ll_assign_hi = astree.mk_assign(
            ll_lhshi,
            ll_rhshi,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        rdefs = xdata.reachingdefs

        astree.add_expr_reachingdefs(ll_rn, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_rm, [rdefs[1]])
        astree.add_expr_reachingdefs(ll_lo, [rdefs[2]])
        astree.add_expr_reachingdefs(ll_hi, [rdefs[3]])

        # high-level assignment

        xd = ARMUnsignedMultiplyAccumulateLongXData(xdata)
        if not xd.is_ok:
            chklogger.logger.error(
                "Error value encountered for UMLAL at %s", iaddr)
            return ([], [])

        hl_lhs = XU.xvariable_to_ast_lval(xd.vlo, xdata, iaddr, astree)
        hl_rhs = XU.xxpr_to_ast_def_expr(xd.rresult, xdata, iaddr, astree)

        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_instr_mapping(hl_assign, ll_assign_lo)
        astree.add_instr_mapping(hl_assign, ll_assign_hi)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhslo)
        astree.add_lval_mapping(hl_lhs, ll_lhslo)
        astree.add_expr_reachingdefs(hl_rhs, rdefs[4:])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        return ([hl_assign], [ll_assign_lo, ll_assign_hi])
