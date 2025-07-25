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

import chb.invariants.XXpr as X
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMMoveXData(ARMOpcodeXData):
    """Data format:
    - variables:
    0: vrd

    - expressions:
    0: xrm
    1: result

    - c expressions:
    0: cresult

    Aggregates:

    - expressions with predicate / ternary assignments

    - nondet:
      - predicate: none
      - ternary:
        0: true assign (constant)
        1: false assign  (constant)

    - predicate:
      0: p
      1: xp

    - ternary:
      0: p
      1: xp
      2: true assign  (constant)
      3: false assign  (constant)

    - c expressions with predicate /ternary assignments

    - nondet: none

    - predicate/ternary:
      0: p
    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vrd(self) -> "XVariable":
        return self.var(0, "vrd")

    @property
    def is_predicate_assign(self) -> bool:
        return self.xdata.is_predicate_assignment

    @property
    def is_nondet_predicate_assign(self) -> bool:
        return self.xdata.is_nondet_predicate_assignment

    @property
    def is_ternary_assign(self) -> bool:
        return self.xdata.is_ternary_assignment

    @property
    def is_nondet_ternary_assign(self) -> bool:
        return self.xdata.is_nondet_ternary_assignment

    @property
    def xrm(self) -> "XXpr":
        return self.xpr(0, "xrm")

    @property
    def result(self) -> "XXpr":
        return self.xpr(1, "result")

    @property
    def is_result_ok(self) -> bool:
        return self.is_xpr_ok(1)

    @property
    def cresult(self) -> "XXpr":
        return self.cxpr(0, "cresult")

    @property
    def is_cresult_ok(self) -> bool:
        return self.is_cxpr_ok(0)

    @property
    def predicate(self) -> "XXpr":
        # known to be valid
        return self.xpr(0, "p")  # known to be valid

    @property
    def xpredicate(self) -> "XXpr":
        return self.xpr(1, "xp")  # known to be valid

    @property
    def cpredicate(self) -> "XXpr":
        return self.cxpr(0, "cxp")

    @property
    def is_cpredicate_ok(self) -> bool:
        return self.is_cxpr_ok(0)

    @property
    def tern_assign_true(self) -> "XXpr":  # known to be valid
        if self.is_nondet_ternary_assign:
            return self.xpr(1, "xp1")
        else:
            return self.xpr(3, "xp1")

    @property
    def tern_assign_false(self) -> "XXpr":  # known to be valid
        if self.is_nondet_ternary_assign:
            return self.xpr(0, "xp2")
        else:
            return self.xpr(2, "xp2")

    def has_instruction_condition(self) -> bool:
        return self.xdata.has_instruction_condition()

    def get_instruction_condition(self) -> "XXpr":
        return self.xdata.get_instruction_condition()

    def has_valid_instruction_c_condition(self) -> bool:
        return self.xdata.has_valid_instruction_c_condition()

    def get_instruction_c_condition(self) -> "XXpr":
        return self.xdata.get_instruction_c_condition()

    def predicate_assignment_ann(self) -> str:
        if self.is_nondet_predicate_assign:
            rhs = "? (unknown predicate)"
        else:
            crhs = (
                " (C:"
                + (str(self.cpredicate) if self.is_cpredicate_ok else "?")
                + ")")
            rhs = str(self.xpredicate) + crhs
        return str(self.vrd) + " := " + rhs

    def ternary_assignment_ann(self) -> str:
        rhs = str(self.tern_assign_true) + " : " + str(self.tern_assign_false)
        if self.is_nondet_ternary_assign:
            rhs = " ? " + rhs
        else:
            rhs = str(self.xpredicate) + " ? " + rhs
        cpred = (
            " (C:"
            + (str(self.cpredicate) if self.is_cpredicate_ok else "?")
            + ")")
        return str(self.vrd) + " := " + rhs + cpred

    @property
    def annotation(self) -> str:
        if self.xdata.instruction_is_subsumed():
            return "subsumed by " + self.xdata.subsumed_by()
        if self.is_ternary_assign or self.is_nondet_ternary_assign:
            return self.ternary_assignment_ann()
        if self.is_predicate_assign or self.is_nondet_predicate_assign:
            return self.predicate_assignment_ann()
        if self.xdata.instruction_subsumes():
            return "subsumes " + ", ".join(self.xdata.subsumes())
        cx = " (C: " + (str(self.cresult) if self.is_cresult_ok else "None") + ")"
        rhs = str(self.result) if self.is_result_ok else str(self.xrm)
        assignment = str(self.vrd) + " := " + rhs + cx
        return self.add_instruction_condition(assignment)


@armregistry.register_tag("MOV", ARMOpcode)
@armregistry.register_tag("MOVW", ARMOpcode)
class ARMMove(ARMOpcode):
    """Moves a constant or copies a register value to a destination register.

    MOV{S}<c> <Rd>, <Rm>

    tags[1]: <c>
    args[0]: {S}
    args[1]: index of op1 in armdictionary
    args[2]: index of op2 in armdictionary
    args[3]: is-wide (thumb)
    args[4]: wide

    xdata format
    ------------
    rdefs[0]: rhs
    rdefs[1..]: rhs (simplified)
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "Move")

    @property
    def mnemonic_stem(self) -> str:
        return self.tags[0]

    @property
    def mnemonic(self) -> str:
        return (
            self.tags[0]
            + ("W" if self.args[3] == 1 else "")
            + ("S" if self.args[0] == 1 else ""))

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1: -2]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1: -2]]

    @property
    def operandstring(self) -> str:
        return ", ".join(str(op) for op in self.operands)

    def is_nop_instruction(self, xdata: InstrXData) -> bool:
        return xdata.is_nop

    def annotation(self, xdata: InstrXData) -> str:
        if len(xdata.tags) == 0:
            # This happens when this instruction is part of an aggregate
            # conditional assignment, but the condition cannot be determined
            return "insufficient information"

        if xdata.is_nop:
            return "NOP"

        xd = ARMMoveXData(xdata)
        return xd.annotation

    def ast_prov_subsumed(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        """Return only low-level instruction with low-level condition."""

        annotations: List[str] = [iaddr, "MOV (subsumed)"]

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs_t, _, _) = self.opargs[1].ast_rvalue(astree)
        ll_rhs_f = astree.mk_lval_expr(ll_lhs)

        cc = self.ast_cc_expr(astree)

        questionx = astree.mk_question(cc, ll_rhs_t, ll_rhs_f)
        ll_assign = astree.mk_assign(
            ll_lhs,
            questionx,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        rdefs = xdata.reachingdefs

        astree.add_expr_reachingdefs(ll_rhs_f, rdefs)

        return ([], [ll_assign])

    def ast_prov_predicate_assign(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData
    ) -> Tuple[List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "MOV (predicate assign)"]

        # low-level assignment

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs, _, _) = self.opargs[1].ast_rvalue(astree)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignment

        xd = ARMMoveXData(xdata)

        if xd.is_nondet_predicate_assign:
            chklogger.logger.warning(
                "Predicate assignment without associated predicate at "
                + "address %s", iaddr)
            return ([], [ll_assign])

        rhs = xd.cpredicate if xd.is_cpredicate_ok else xd.xpredicate
        lhs = xd.vrd
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
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
        astree.add_expr_reachingdefs(hl_rhs, rdefs[1:])
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[0]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        if astree.has_register_variable_intro(iaddr):
            rvintro = astree.get_register_variable_intro(iaddr)
            if rvintro.has_cast():
                astree.add_expose_instruction(hl_assign.instrid)

        return ([hl_assign], [ll_assign])


    def ast_prov_ternary_assign(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData
    ) -> Tuple[List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "MOV (ternary assign)"]

        # low-level assignment

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs, _, _) = self.opargs[1].ast_rvalue(astree)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignment

        xd = ARMMoveXData(xdata)

        if xd.is_nondet_ternary_assign:
            chklogger.logger.warning(
                "Ternary assignment without associated predicate at address %s",
                iaddr)
            return ([], [ll_assign])

        rhsp = xd.cpredicate if xd.is_cpredicate_ok else xd.xpredicate
        rhs1 = xd.tern_assign_true
        rhs2 = xd.tern_assign_false
        lhs = xd.vrd
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)
        hl_rhsp = XU.xxpr_to_ast_def_expr(rhsp, xdata, iaddr, astree)
        hl_rhs1 = XU.xxpr_to_ast_def_expr(rhs1, xdata, iaddr, astree)
        hl_rhs2 = XU.xxpr_to_ast_def_expr(rhs2, xdata, iaddr, astree)
        hl_rhs = astree.mk_question(hl_rhsp, hl_rhs1, hl_rhs2)

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
        astree.add_expr_reachingdefs(hl_rhs, rdefs[1:])
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[0]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        if astree.has_register_variable_intro(iaddr):
            rvintro = astree.get_register_variable_intro(iaddr)
            if rvintro.has_cast():
                astree.add_expose_instruction(hl_assign.instrid)

        return ([hl_assign], [ll_assign])


    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "MOV"]

        if xdata.is_nop:
            nopinstr = astree.mk_nop_instruction(
                "MOV:NOP",
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            astree.add_instr_address(nopinstr, [iaddr])

            return ([], [nopinstr])

        if xdata.instruction_is_subsumed():
            return self.ast_prov_subsumed(astree, iaddr, bytestring, xdata)

        xd = ARMMoveXData(xdata)

        if xdata.instruction_subsumes():
            if xd.is_predicate_assign or xd.is_nondet_predicate_assign:
                return self.ast_prov_predicate_assign(
                    astree, iaddr, bytestring, xdata)

            elif xd.is_ternary_assign or xd.is_nondet_ternary_assign:
                return self.ast_prov_ternary_assign(
                    astree, iaddr, bytestring, xdata)

            else:
                chklogger.logger.warning(
                    "MOV instruction at %s is part of an aggregate that is "
                    + "not yet supported",
                    iaddr)
            return ([], [])

        # low-level assignment

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs, _, _) = self.opargs[1].ast_rvalue(astree)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignment

        xd = ARMMoveXData(xdata)

        if xd.is_cresult_ok:
            rhs = xd.cresult
        elif xd.is_result_ok:
            rhs = xd.result
        else:
            rhs = xd.xrm

        lhs = xd.vrd
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
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
        astree.add_expr_reachingdefs(hl_rhs, rdefs[1:])
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[0]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        if astree.has_register_variable_intro(iaddr):
            rvintro = astree.get_register_variable_intro(iaddr)
            if rvintro.has_cast():
                astree.add_expose_instruction(hl_assign.instrid)

        return ([hl_assign], [ll_assign])
