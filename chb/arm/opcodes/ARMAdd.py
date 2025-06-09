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

from typing import cast, List, Optional, Tuple, TYPE_CHECKING

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
    from  chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.VarInvariantFact import ReachingDefFact
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XprCompound, XprConstant, XXpr


class ARMAddXData(ARMOpcodeXData):
    """Add <rd> <rn> <rm>  ==> result

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
    def vrd(self) -> "XVariable":
        return self.var(0, "vrd")

    @property
    def xrn(self) -> "XXpr":
        return self.xpr(0, "xrn")

    @property
    def xrm(self) -> "XXpr":
        return self.xpr(1, "xrm")

    @property
    def jt_xxrn(self) -> "XXpr":
        """Part of jumptable."""
        return self.xpr(1, "xxrn")

    @property
    def is_jt_xxrn_ok(self) -> bool:
        return self.is_xpr_ok(1)

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

    @property
    def annotation(self) -> str:
        if self.xdata.is_aggregate_jumptable:
            if self.is_jt_xxrn_ok:
                return "jump-table: " + str(self.jt_xxrn)
            else:
                return "jump-table: " + str(self.xrn)
        assignment = str(self.vrd) + " := " + self.result_simplified
        return self.add_instruction_condition(assignment)


@armregistry.register_tag("ADD", ARMOpcode)
class ARMAdd(ARMOpcode):
    """Add (register, constant)

    ADD{S}<c> <Rd>, <Rn>, <Rm>{, <shift>} (arm)
    ADD{S}<c> <Rd>, <Rn>, #<const> (arm, thumb)
    ADD{S}<c>.W <Rd>, <Rn>, #<const> (thumb)
    ADD{S}<c> <Rdn>, #<const> (thumb)
    ADD<c> <Rdn>, <Rm> (thumb)
    ADD<c> SP, <Rm> (thumb)
    ADD<c> <Rd>, SP, #<const> (thumb)
    ADD<c> SP, SP, #<const> (thumb)
    ADD<c> <Rdm>, SP, <Rdm> (thumb)

    tags[1]: <c>
    args[0]: {S}
    args[1]: index of op1 in armdictionary
    args[2]: index of op2 in armdictionary
    args[3]: index of op3 in armdictionary
    args[4]: is-wide (thumb)

    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "Add")

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
        xd = ARMAddXData(xdata)
        return xd.annotation

    # --------------------------------------------------------------------------
    # AddWithCarry()
    #
    # (bits(N), bit, bit) AddWithCarry(bitsN) x, bits(N), bit carry_in)
    #   unsigned_sum = UInt(x) + UInt(y) + UInt(carry_in);
    #   signed_sum = SInt(x) + SInt(y) + UInt(carry_in);
    #   result = unsigned_sum<N-1:0>;
    #   carry_out = if UInt(result) == unsigned_sum then '0' else '1';
    #   overflow = if SInt(result) == signed_sum then '0' else '1';
    #   return (result, carry_out, overflow);
    #
    # if ConditionPassed() then
    #   (result, carry, overflow) = AddWithCarry(R[n], op2, '0');
    #   if d == 15 then
    #     ALUWritePC(result);
    #   else
    #     R[d] = result;
    #     if setflags then
    #       APSR.N = result<31>;
    #       APSR.Z = IsZeroBit(result);
    #       APSR.C = carry;
    #       APSR.V = overflow;
    #
    # where op2 can be imm32 (immediate) or shifted (shifted register value)
    # --------------------------------------------------------------------------

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "ADD"]

        if xdata.is_aggregate_jumptable:
            chklogger.logger.warning(
                "ADD: aggregate jumptable at address %s not yet handled",
                iaddr)
            return ([], [])

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

        xd = ARMAddXData(xdata)

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
                "ADD: Encountered error value for rhs at address %s", iaddr)
            return ([], [ll_assign])

        lhs = xd.vrd
        rhs1 = xd.xrn
        rhs2 = xd.xrm
        rrhs1 = xd.xxrn if xd.is_xxrn_ok else xd.xrn
        rrhs2 = xd.xxrm if xd.is_xxrm_ok else xd.xrm

        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)

        if str(lhs) == "PC":
            chklogger.logger.info(
                "Add (ADD) instruction at address %s sets PC", iaddr)

        hl_lhs_type = hl_lhs.ctype(astree.ctyper)

        # resulting expression is a stack address
        if (
                (str(rrhs1) == "SP" or rrhs1.is_stack_address)
                and xrhs.is_stack_address):
            annotations.append("stack address")
            xrhs = cast("XprCompound", xrhs)
            stackoffset = xrhs.stack_address_offset()
            rhslval = astree.mk_stack_variable_lval(stackoffset)
            hl_rhs: AST.ASTExpr = astree.mk_address_of(rhslval)

        # resulting expression is a pc-relative address
        elif str(rrhs1) == "PC" or str(rhs2) == "PC":
            annotations.append("PC-relative")
            if xrhs.is_int_constant:
                rhsexpr = XU.xxpr_to_ast_def_expr(xrhs, xdata, iaddr, astree)
                rhsval = cast("XprConstant", xrhs).intvalue
                if xrhs.is_string_reference:
                    saddr = hex(rhsval)
                    cstr = xrhs.constant.string_reference()
                    hl_rhs = astree.mk_string_constant(
                        rhsexpr, cstr, saddr)
                else:
                    hl_rhs = astree.mk_global_address_constant(
                        rhsval, rhsexpr)
            else:
                hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)

        elif rhs.is_addressof_var:
            hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)
            if rhs.is_constant_expression:
                astree.set_ssa_value(str(hl_lhs), hl_rhs)

        else:
            hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # Workaround for a deficiency in the defuse-high invariant generation;
        # ensures that the instruction is preserved by the code transformer
        # even if there are no uses for the lhs.
        # An INFO message is logged if this is actually used in the Code
        # Transformer.
        if rdefs[0] is not None:
            if iaddr in [str(d) for d in rdefs[0].deflocations]:
                astree.add_expose_instruction(hl_assign.instrid)

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
