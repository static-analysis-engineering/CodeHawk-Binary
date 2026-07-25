# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2026  Aarno Labs LLC
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
    from chb.arm.ARMOperandKind import ARMShiftedRegisterOp
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMReverseSubtractCarryXData(ARMOpcodeXData):
    """Data format:
    - variables:
    0: vrd

    - expressions:
    0: xrn
    1. xrm
    2: result
    3: rresult (result rewritten)

    - c expressions:
    0: cresult

    Aggregate: ARMWideReverseSubtract

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
    11: xxrn_w
    12: xxrm_w

    - c exressions
    0: cresult_w
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
    def is_wide_reverse_subtract(self) -> bool:
        return self.xdata.is_wide_reversesubtract

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
    def is_result_ok(self) -> bool:
        return self.is_xpr_ok(2)

    @property
    def rresult(self) -> "XXpr":
        return self.xpr(3, "rresult")

    @property
    def is_rresult_ok(self) -> bool:
        return self.is_xpr_ok(3)

    @property
    def cresult(self) -> "XXpr":
        return self.cxpr(0, "cresult")

    @property
    def is_cresult_ok(self) -> bool:
        return self.is_cxpr_ok(0)

    @property
    def result_simplified(self) -> str:
        if self.is_result_ok and self.is_rresult_ok:
            return simplify_result(
                self.xdata.args[3], self.xdata.args[4], self.result, self.rresult)
        else:
            return str(self.xrm) + " - " + str(self.xrn)

    @property
    def xxrn(self) -> "XXpr":
        return self.xpr(4, "xxrn")

    @property
    def is_xxrn_ok(self) -> bool:
        return self.is_xpr_ok(4)

    @property
    def xxrm(self) -> "XXpr":
        return self.xpr(5, "xxrm")

    @property
    def is_xxrm_ok(self) -> bool:
        return self.is_xpr_ok(5)

    # Wide add aggregate

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
        if self.is_wide_reverse_subtract:
            lhs = "(" + str(self.vrdhi) + ", " + str(self.vrdlo) + ")"
            rhs1 = "(" + str(self.xxrnhi) + ", " + str(self.xxrnlo) + ")"
            rhs2 = "(" + str(self.xxrmhi) + ", " + str(self.xxrmlo) + ")"
            cx = " (C: " + (str(self.cresult_w) if self.is_cresult_w_ok else "None") + ")"
            assignment = lhs + " := " + rhs2 + " - " + rhs1 + cx
        else:
            assignment = str(self.vrd) + " := " + self.result_simplified
        return self.add_instruction_condition(assignment)


@armregistry.register_tag("RSC", ARMOpcode)
class ARMReverseSubtractCarry(ARMOpcode):
    """Subtracts a value from a register, adds the carry and saves the result in a register.

    RSC{S}<c> <Rd>, <Rn>, #<const>
    RSC{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
    RSC{S}<c> <rd>, <Rn>, <Rm>, <type <Rs>

    tags[1]: <c>
    args[0]: {S}
    args[1]: index of op1 in armdictionary
    args[2]: index of op2 in armdictionary
    args[3]: index of op3 in armdictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "ReverseSubtractCarry")

    @property
    def is_writeback(self) -> bool:
        return self.args[0] == 1

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

    def mnemonic_extension(self) -> str:
        wb = "S" if self.is_writeback else ""
        cc = ARMOpcode.mnemonic_extension(self)
        return wb + cc

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMReverseSubtractCarryXData(xdata)
        return xd.annotation
