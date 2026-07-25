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


class ARMSubtractCarryXData(ARMOpcodeXData):
    """
    Aggregate: ARMWideSubtract

    - variables
    0: vrdlo
    1: vrdhi

    - expressions
    0: xrnlo
    1: xrnhi
    2: xrmlo
    3: xrmhi
    4: rresult
    5: rresultlo
    6: rresulthi
    7: xxrnlo
    8: xxrnhi
    9: xxrmlo
    10: xxrmhi

    - c exressions
    0: cresult
    1: cresultlo
    2: cresulthi

    rdefs:
    0: xrnlo
    1: xrnhi
    2: xrmlo
    3: xrmhi

    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def is_wide_subtract(self) -> bool:
        return self.xdata.is_wide_subtract

    @property
    def vrd(self) -> "XVariable":
        return self.var(0, "vrd")

    @property
    def xrn(self) -> "XXpr":
        return self.xpr(0, "xrn")

    @property
    def xrm(self) -> "XXpr":
        return self.xpr(1, "xrm")

    @property
    def result(self) -> "XXpr":
        return self.xpr(2, "result")

    @property
    def rresult(self) -> "XXpr":
        return self.xpr(3, "rresult")

    @property
    def result_simplified(self) -> str:
        return simplify_result(
            self.xdata.args[3], self.xdata.args[4], self.result, self.rresult)

    # Wide subtract aggregate

    @property
    def vrdlo(self) -> "XVariable":
        return self.var(0, "vrdlo")

    @property
    def vrdhi(self) -> "XVariable":
        return self.var(1, "vrdhi")

    @property
    def xrnlo(self) -> "XXpr":
        return self.xpr(0, "xrnlo")

    @property
    def xrnhi(self) -> "XXpr":
        return self.xpr(1, "xrnhi")

    @property
    def xrmlo(self) -> "XXpr":
        return self.xpr(2, "xrmlo")

    @property
    def xrmhi(self) -> "XXpr":
        return self.xpr(3, "xrmhi")

    @property
    def rresult_w(self) -> "XXpr":
        return self.xpr(4, "rresult")

    @property
    def rresultlo(self) -> "XXpr":
        return self.xpr(5, "rresultlo")

    @property
    def rresulthi(self) -> "XXpr":
        return self.xpr(6, "rresulthi")

    @property
    def xxrnlo(self) -> "XXpr":
        return self.xpr(7, "xxrnlo")

    @property
    def xxrnhi(self) -> "XXpr":
        return self.xpr(8, "xxrnhi")

    @property
    def xxrmlo(self) -> "XXpr":
        return self.xpr(9, "xxrmlo")

    @property
    def xxrmhi(self) -> "XXpr":
        return self.xpr(10, "xxrmhi")

    @property
    def xxrn_w(self) -> "XXpr":
        return self.xpr(11, "xxrn_w")

    @property
    def xxrm_w(self) -> "XXpr":
        return self.xpr(12, "xxrm_w")

    @property
    def cresult_w(self) -> "XXpr":
        return self.cxpr(0, "cresult")

    @property
    def is_cresult_w_ok(self) -> bool:
        return self.is_cxpr_ok(0)

    @property
    def cresultlo(self) -> "XXpr":
        return self.cxpr(1, "cresultlo")

    @property
    def cresulthi(self) -> "XXpr":
        return self.cxpr(2, "cresulthi")

    @property
    def annotation(self) -> str:
        if self.is_wide_subtract:
            lhs = "(" + str(self.vrdhi) + ", " + str(self.vrdlo) + ")"
            rhs1 = "(" + str(self.xxrnhi) + ", " + str(self.xxrnlo) + ")"
            rhs2 = "(" + str(self.xxrmhi) + ", " + str(self.xxrmlo) + ")"
            cx = " (C: " + (str(self.cresult_w) if self.is_cresult_w_ok else "None") + ")"
            assignment = lhs + " := " + rhs1 + " - " + rhs2 + cx
        else:
            assignment = str(self.vrd) + " := " + self.result_simplified
        return self.add_instruction_condition(assignment)


@armregistry.register_tag("SBC", ARMOpcode)
class ARMSubtractCarry(ARMOpcode):
    """Subtracts an imm. or register value from a register and the value of NOT carry.

    SBC{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}

    tags[1]: <c>
    args[0]: {S}
    args[1]: index of op1 in armdictionary
    args[2]: index of op2 in armdictionary
    args[3]: index of op3 in armdictionary
    args[4]: is-wide (thumb)
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "SubtractCarry")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wb = "S" if self.is_writeback else ""
        wide = ".W" if self.args[4] == 1 else ""
        return wb + cc + wide

    @property
    def is_writeback(self) -> bool:
        return self.args[0] == 1

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMSubtractCarryXData(xdata)
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

        annotations: List[str] = [iaddr, "SBC"]

        # low-level assignment

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_op1, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_op2, _, _) = self.opargs[2].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("minus", ll_op1, ll_op2)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        rdefs = xdata.reachingdefs

        astree.add_expr_reachingdefs(ll_op1, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_op2, [rdefs[1]])

        # high-level assignment

        xd = ARMSubtractCarryXData(xdata)
        if not xd.is_ok:
            chklogger.logger.error(
                "Encountered error value at address %s", iaddr)
            return ([], [])

        lhs = xd.vrd
        rhs1 = xd.xrn
        rhs2 = xd.xrm
        rhs3 = xd.rresult

        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)
        hl_rhs = XU.xxpr_to_ast_def_expr(rhs3, xdata, iaddr, astree)

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(hl_rhs, rdefs[2:])
        astree.add_expr_reachingdefs(ll_rhs, rdefs[:2])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        return ([hl_assign], [ll_assign])
