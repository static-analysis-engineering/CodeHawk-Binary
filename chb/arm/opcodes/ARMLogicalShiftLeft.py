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


class ARMLogicalShiftLeftXData(ARMOpcodeXData):

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
    def result_simplified(self) -> str:
        return simplify_result(
            self.xdata.args[3], self.xdata.args[4], self.result, self.rresult)

    @property
    def annotation(self) -> str:
        assignment = str(self.vrd) + " := " + self.result_simplified
        return self.add_instruction_condition(assignment)


@armregistry.register_tag("LSL", ARMOpcode)
class ARMLogicalShiftLeft(ARMOpcode):
    """Shifts a register value left by an immediate value, or value in a register.

    LSL{S}<c> <Rd>, <Rm>, #<imm5>
    LSL{S}<c>.W <Rd>, <Rm>, #<imm5>

    LSL{S}<c> <Rdn>, <Rm>
    LSL{S}<c>.W <Rd>, <Rn>, <Rm>
    LSL{S}<c> <Rd>, <Rn>, <Rm>

    tags[1]: <c>
    args[0]: {S}
    args[1]: index of rd in armdictionary
    args[2]: index of rn in armdictionary
    args[3]: index of rm in armdictionary
    args[4]: is-wide (thumb)

    xdata format: a:vxxxxrrdh
    -------------------------
    vars[0]: lhs
    xprs[0]: xrn
    xprs[1]: xrm
    xprs[2]: xrn << xrm
    xprs[3]: xrn << xrm (simplified)
    rdefs[0]: xrm
    rdefs[1]: xrn
    rdefs[2..]: xrn << xrm (simplified)
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[4] == 1 else ""
        return cc + wide

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:-1]]

    @property
    def mnemonic_stem(self) -> str:
        return self.tags[0]

    @property
    def mnemonic(self) -> str:
        mnem = self.tags[0]
        if self.is_writeback:
            return mnem + "S"
        else:
            return mnem

    @property
    def is_writeback(self) -> bool:
        return self.args[0] == 1

    def lsl_xdata(self, xdata: InstrXData) -> ARMLogicalShiftLeftXData:
        return ARMLogicalShiftLeftXData(xdata)

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMLogicalShiftLeftXData(xdata)
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

        annotations: List[str] = [iaddr, "LSL"]

        # low-level assignment

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs1, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_rhs2, _, _) = self.opargs[2].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("lsl", ll_rhs1, ll_rhs2)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignment

        xd = ARMLogicalShiftLeftXData(xdata)
        if not xd.is_ok:
            chklogger.logger.error(
                "Encountered error value at address %s", iaddr)
            return ([], [])

        lhs = xd.vrd
        rhs1 = xd.xrn
        rhs2 = xd.xrm
        rresult = xd.rresult
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)
        hl_rhs = XU.xxpr_to_ast_def_expr(rresult, xdata, iaddr, astree)

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
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[0], rdefs[1]])
        astree.add_expr_reachingdefs(ll_rhs1, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_rhs2, [rdefs[1]])
        astree.add_expr_reachingdefs(hl_rhs, rdefs[2:])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        return ([hl_assign], [ll_assign])
