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

from typing import List, Optional, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XprCompound
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.VarInvariantFact import ReachingDefFact
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMAddCarryXData(ARMOpcodeXData):
    """Adc <rd> <rn> <rm>  ==> result

    Data format (regular)
    - variables:
    0: vrd

    - expressions:
    0: xrn
    1: xrm
    2: result
    3: rresult (result, rewritten)
    4: xxrn (xrn, rewritten)
    5: xxrm (xrm, rewritten)

    - c expressions:
    0: cresult

    rdefs[0]: xrn
    rdefs[1]: xrm
    rdefs[2:..]: reaching definitions for simplified result expression
    uses[0]: vrd
    useshigh[0]: vrd

    Data format (as part of jump table)
    - expressions:
    0: xrn
    1: xxrn (xrn, rewritten)

    rdefs[0]: xrn
    rdefs[1:]: reaching definitions for xxrn
    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def is_wide_add(self) -> bool:
        return self.xdata.is_wide_add

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
            return str(self.xrn) + " + " + str(self.xrm)

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

    @property
    def rn_rdef(self) -> Optional["ReachingDefFact"]:
        return self._xdata.reachingdefs[0]

    @property
    def rm_rdef(self) -> Optional["ReachingDefFact"]:
        return self._xdata.reachingdefs[1]

    # Wide add aggregate

    @property
    def vrdlohi(self) -> "XVariable":
        return self.binary_wopvar("vrdlohi")

    @property
    def vrdlo(self) -> "XVariable":
        return self.binary_wopvar("vrdlo")

    @property
    def vrdhi(self) -> "XVariable":
        return self.binary_wopvar("vrdhi")

    @property
    def xrnlo(self) -> "XXpr":
        return self.binary_wopxpr("xrnlo")

    @property
    def xrnhi(self) -> "XXpr":
        return self.binary_wopxpr("xrnhi")

    @property
    def xrmlo(self) -> "XXpr":
        return self.binary_wopxpr("xrmlo")

    @property
    def xrmhi(self) -> "XXpr":
        return self.binary_wopxpr("xrmhi")

    @property
    def rresultw(self) -> "XXpr":
        return self.binary_wopxpr("rresultw")

    @property
    def is_rresultw_ok(self) -> bool:
        return self.is_binary_wopxpr_ok("rresultw")

    @property
    def rresultlo(self) -> "XXpr":
        return self.binary_wopxpr("rresultlo")

    @property
    def rresulthi(self) -> "XXpr":
        return self.binary_wopxpr("rresulthi")

    @property
    def xxrnlo(self) -> "XXpr":
        return self.binary_wopxpr("xxrnlo")

    @property
    def xxrnhi(self) -> "XXpr":
        return self.binary_wopxpr("xxrnhi")

    @property
    def xxrmlo(self) -> "XXpr":
        return self.binary_wopxpr("xxrmlo")

    @property
    def xxrmhi(self) -> "XXpr":
        return self.binary_wopxpr("xxrmhi")

    @property
    def xxrnw(self) -> "XXpr":
        return self.binary_wopxpr("xxrnw")

    @property
    def xxrmw(self) -> "XXpr":
        return self.binary_wopxpr("xxrmw")

    @property
    def cresultw(self) -> "XXpr":
        return self.binary_wopcxpr("cresultw")

    @property
    def is_cresultw_ok(self) -> bool:
        return self.is_binary_wopcxpr_ok("cresultw")

    @property
    def cresultlo(self) -> "XXpr":
        return self.binary_wopcxpr("cresultlo")

    @property
    def cresulthi(self) -> "XXpr":
        return self.binary_wopcxpr("cresulthi")

    @property
    def annotation(self) -> str:
        if self.is_wide_add:
            lhs = str(self.vrdlohi)
            rhs = str(self.rresultw)
            cx = " (C: " + (str(self.cresultw) if self.is_cresultw_ok else "None") + ")"
            assignment = lhs + " := " + rhs + cx
        else:
            assignment = str(self.vrd) + " := " + self.result_simplified
        return self.add_instruction_condition(assignment)


@armregistry.register_tag("ADC", ARMOpcode)
class ARMAddCarry(ARMOpcode):
    """Adds an immediate/register value and the carry flag to a register value.

    ADC<c> <Rd>, <Rn>, #<const>

    tags[1]: <c>
    args[0]: {S}
    args[1]: index of op1 in armdictionary
    args[2]: index of op2 in armdictionary
    args[3]: index of op3 in armdictionary
    args[4]: is-wide (thumb)

    xdata format: a:vxxxxrrdh
    -------------------------
    vars[0]: lhs (Rd)
    xprs[0]: rhs1 (Rn)
    xprs[1]: rhs2 (Rm)
    xprs[2]: rhs1 + rhs2
    xprs[3]: rhs1 + rhs2 (simplified)
    rdefs[0]: rhs1
    rdefs[1]: rhs2
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "AddCarry")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:-1]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:-1]]

    @property
    def writeback(self) -> bool:
        return self.args[0] == 1

    def mnemonic_extension(self) -> str:
        wb = "S" if self.writeback else ""
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[4] == 1 else ""
        return wb + cc + wide

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMAddCarryXData(xdata)
        return xd.annotation

    def ast_prov_wide_add(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "ADC (wide-add)"]

        # low-level assignment

        (ll_lhs, _, _) = self.operands[0].ast_lvalue(astree)
        (ll_op1, _, _) = self.operands[1].ast_rvalue(astree)
        (ll_op2, _, _) = self.operands[2].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("plus", ll_op1, ll_op2)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignment

        xd = ARMAddCarryXData(xdata)

        lhs = xd.vrdlohi
        if xd.is_cresultw_ok:
            rhs = xd.cresultw
        elif xd.is_rresultw_ok:
            rhs = xd.rresultw
        else:
            chklogger.logger.warning(
                "Encountered error value for rhs of wide-add at %s", iaddr)
            return ([], [ll_assign])

        rdefdoubles = xdata.reachingdefdoubles
        if len(rdefdoubles) == 0:
            rdefdoubles = xdata.reachingdefs
        defusedoubles = xdata.defusedoubles
        defuseshigh = xdata.defuseshigh

        hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree, rhs=rhs)
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
        astree.add_expr_reachingdefs(hl_rhs, rdefdoubles)
        astree.add_lval_defuses(hl_lhs, defusedoubles[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        if astree.has_register_variable_intro(iaddr):
            rvintro = astree.get_register_variable_intro(iaddr)
            if rvintro.has_cast():
                astree.add_expose_instruction(hl_assign.instrid)

        astree.add_expose_instruction(hl_assign.instrid)

        return ([hl_assign], [ll_assign])

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        xd = ARMAddCarryXData(xdata)

        if xdata.instruction_subsumes():
            if xd.is_wide_add:
                return self.ast_prov_wide_add(
                    astree, iaddr, bytestring, xdata)

        annotations: List[str] = [iaddr, "ADC"]

        # low-level assignment

        (ll_lhs, _, _) = self.operands[0].ast_lvalue(astree)
        (ll_op1, _, _) = self.operands[1].ast_rvalue(astree)
        (ll_op2, _, _) = self.operands[2].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("plus", ll_op1, ll_op2)

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

        def has_cast() -> bool:
            return (
                astree.has_register_variable_intro(iaddr)
                and astree.get_register_variable_intro(iaddr).has_cast())

        if xd.is_cresult_ok and xd.is_rresult_ok:
            rhs = xd.cresult
            xrhs = xd.rresult

        elif xd.is_rresult_ok:
            rhs = xd.rresult
            xrhs = xd.rresult

        elif xd.is_result_ok:
            rhs = xd.result
            xrhs = xd.result

        else:
            chklogger.logger.error(
                "ADC: Encountered error value for rhs at address %s", iaddr)
            return ([], [ll_assign])

        lhs = xd.vrd
        rhs1 = xd.xrn
        rhs2 = xd.xrm
        rrhs1 = xd.xxrn if xd.is_xxrn_ok else xd.xrn
        rrhs2 = xd.xxrm if xd.is_xxrm_ok else xd.xrm

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

        if astree.has_register_variable_intro(iaddr):
            rvintro = astree.get_register_variable_intro(iaddr)
            if rvintro.has_cast():
                astree.add_expose_instruction(hl_assign.instrid)

        return ([hl_assign], [ll_assign])
