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

import chb.util.fileutil as UF

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMBitwiseExclusiveOrXData(ARMOpcodeXData):
    """Data format:
    - variables:
    0: vrd

    - expressions:
    0: xrn
    1: xrm
    2: result
    3: rresult (result, simplified)

    - c expressions:
    0: cresult
    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

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
        if self.is_rresult_ok:
            return simplify_result(
                self.xdata.args[3], self.xdata.args[4], self.result, self.rresult)
        else:
            return str(self.result)

    @property
    def annotation(self) -> str:
        cr = str(self.cresult) if self.is_cresult_ok else ""
        cr = " (C: " + cr + ")"
        assignment = str(self.vrd) + " := " + self.result_simplified + cr
        return self.add_instruction_condition(assignment)


@armregistry.register_tag("EOR", ARMOpcode)
class ARMBitwiseExclusiveOr(ARMOpcode):
    """Bitwise exclusive or instruction (register, register-shifted, and immediate)

    EOR{S}<c> <Rd>, <Rn>{, <shift>}
    EOR{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>

    tags[1]: <c>
    args[0]: {S}
    args[1]: index of op1 in armdictionary
    args[2]: index of op2 in armdictionary
    args[3]: index of op3 in armdictionary
    args[4]: is-wide (thumb)

    xdata format:
    -------------
    rdefs[0]: rhs1
    rdefs[1]: rhs2
    rdefs[2:.]: result
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "BitwiseExclusiveOr")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[4] == 1 else ""
        return cc + wide

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1: -1]]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMBitwiseExclusiveOrXData(xdata)
        return xd.annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "EOR"]

        (ll_lhs, _, _) = self.operands[0].ast_lvalue(astree)
        (ll_op1, _, _) = self.operands[0].ast_rvalue(astree)
        (ll_op2, _, _) = self.operands[0].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("bxor", ll_op1, ll_op2)

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

        xd = ARMBitwiseExclusiveOrXData(xdata)

        if xd.is_cresult_ok:
            rhs = xd.cresult
        elif xd.is_rresult_ok:
            rhs = xd.rresult
        else:
            rhs = xd.result

        lhs = xd.vrd
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)
        hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)

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
