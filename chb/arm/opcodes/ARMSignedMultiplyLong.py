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


class ARMSignedMultiplyLongXData(ARMOpcodeXData):

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

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
    def loresult(self) -> "XXpr":
        return self.xpr(2, "loresult")

    @property
    def hiresult(self) -> "XXpr":
        return self.xpr(3, "hiresult")

    @property
    def loresultr(self) -> "XXpr":
        return self.xpr(4, "loresultr")

    @property
    def hiresultr(self) -> "XXpr":
        return self.xpr(5, "hiresultr")

    @property
    def resultlo_simplified(self) -> str:
        return simplify_result(
            self.xdata.args[2], self.xdata.args[4], self.loresult, self.loresultr)

    @property
    def resulthi_simplified(self) -> str:
        return simplify_result(
            self.xdata.args[5], self.xdata.args[7], self.hiresult, self.hiresultr)

    @property
    def annotation(self) -> str:
        assignment1 = str(self.vlo) + " := " + self.resultlo_simplified
        assignment2 = str(self.vhi) + " := " + self.resulthi_simplified
        return self.add_instruction_condition(assignment1 + "; " + assignment2)


@armregistry.register_tag("SMULL", ARMOpcode)
class ARMSignedMultiplyLong(ARMOpcode):
    """Multiplies two signed 32-bit signed values to produce a 64-bit result

    SMULL{S}<c> <RdLo>, <RdHi>, <Rn>, <Rm>

    tags[1]: <c>
    args[0]: flags are set
    args[1]: index of RdLo in armdictionary
    args[2]: index of RdHi in armdictionary
    args[3]: index of Rn in armdictionary
    args[4]: index of Rm in armdictionary
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "SignedMultiplyLong")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:]]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMSignedMultiplyLongXData(xdata)
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

        annotations: List[str] = [iaddr, "SMULL"]

        # low-level assignment

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_lhs2, _, _) = self.opargs[1].ast_lvalue(astree)
        (ll_op1, _, _) = self.opargs[2].ast_rvalue(astree)
        (ll_op2, _, _) = self.opargs[3].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("mult", ll_op1, ll_op2)
        e32 = astree.mk_integer_constant(0x10000000)
        ll_rhs = astree.mk_binary_op("div", ll_rhs, e32)
        ll_rhs2 = astree.mk_binary_op("mod", ll_rhs, e32)

        ll_assign1 = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)
        ll_assign2 = astree.mk_assign(
            ll_lhs2,
            ll_rhs2,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        rdefs = xdata.reachingdefs

        astree.add_expr_reachingdefs(ll_op1, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_op2, [rdefs[1]])

        # high-level assignment

        xd = ARMSignedMultiplyLongXData(xdata)
        if not xd.is_ok:
            chklogger.logger.error(
                "Encountered error value at address %s", iaddr)
            return ([], [])

        lhs = xd.vlo
        lhs2 = xd.vhi
        rhs1 = xd.xrn
        rhs2 = xd.xrm
        rhslo = xd.loresult
        rhshi = xd.hiresult

        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)
        hl_lhs2 = XU.xvariable_to_ast_lval(lhs2, xdata, iaddr, astree)
        hl_rhs = XU.xxpr_to_ast_def_expr(rhslo, xdata, iaddr, astree)
        hl_rhs2 = XU.xxpr_to_ast_def_expr(rhshi, xdata, iaddr, astree)

        hl_assign1 = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)
        hl_assign2 = astree.mk_assign(
            hl_lhs2,
            hl_rhs2,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_instr_mapping(hl_assign1, ll_assign1)
        astree.add_instr_mapping(hl_assign2, ll_assign2)
        astree.add_instr_address(hl_assign1, [iaddr])
        astree.add_instr_address(hl_assign2, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_expr_mapping(hl_rhs2, ll_rhs2)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_lval_mapping(hl_lhs2, ll_lhs2)
        astree.add_expr_reachingdefs(hl_rhs, rdefs[2:])
        astree.add_expr_reachingdefs(ll_rhs, rdefs[:2])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses(hl_lhs2, defuses[1])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])
        astree.add_lval_defuses_high(hl_lhs2, defuseshigh[1])

        return ([hl_assign1, hl_assign2], [ll_assign1, ll_assign2])
