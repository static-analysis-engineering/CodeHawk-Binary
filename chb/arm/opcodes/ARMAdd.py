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

    xdata format: a:vxxxxxxrrdh
    -------------------------
    vars[0]: vrd (Rd)
    xprs[0]: xrn (Rn)
    xprs[1]: xrm (Rm)
    xprs[2]: result: xrn + xrm
    xprs[3]: rresult: xrn + xrm (rewritten)
    xprs[4]: xxrn (xrn rewritten)
    xprs[5]: xxrm (xrm rewritten)
    xprs[6]: tcond (optional)
    xprs[7]: fcond (optional)
    rdefs[0]: xrn
    rdefs[1]: xrm
    rdefs[2:..]: reaching definitions for simplified result expression
    uses[0]: vrd
    useshigh[0]: vrd
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
    def result_simplified(self) -> str:
        return simplify_result(
            self.xdata.args[3], self.xdata.args[4], self.result, self.rresult)

    @property
    def xxrn(self) -> "XXpr":
        return self.xpr(4, "xxrn")

    @property
    def xxrm(self) -> "XXpr":
        return self.xpr(5, "xxrm")

    @property
    def rn_rdef(self) -> Optional["ReachingDefFact"]:
        return self._xdata.reachingdefs[0]

    @property
    def rm_rdef(self) -> Optional["ReachingDefFact"]:
        return self._xdata.reachingdefs[1]

    @property
    def annotation(self) -> str:
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
        if xd.is_ok:
            return xd.annotation
        else:
            return "Error Value"

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

        xd = ARMAddXData(xdata)
        annotations: List[str] = [iaddr, "ADD"]

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

        if not xdata.is_ok:
            chklogger.logger.error("Error value encountered at %s", iaddr)
            return ([], [])

        lhs = xd.vrd
        rhs1 = xd.xrn
        rhs2 = xd.xrm
        rhs3 = xd.rresult
        rrhs1 = xd.xxrn
        rrhs2 = xd.xxrm

        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        if rhs3.is_string_reference:
            ctype = astree.astree.mk_pointer_type(astree.astree.char_type)
            hl_lhs = XU.xvariable_to_ast_lvals(
                lhs,
                xdata,
                astree,
                ispointer=True,
                ctype=ctype)[0]
        else:
            hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)

        if str(lhs) == "PC":
            chklogger.logger.info(
                "Add (ADD) instruction at address %s sets PC", iaddr)

        hl_lhs_type = hl_lhs.ctype(astree.ctyper)

        def pointer_arithmetic_expr() -> AST.ASTExpr:
            hl_rhs1 = XU.xxpr_to_ast_def_expr(rrhs1, xdata, iaddr, astree)
            hl_rhs2 = XU.xxpr_to_ast_def_expr(rrhs2, xdata, iaddr, astree)
            hl_rhs1_type = hl_rhs1.ctype(astree.ctyper)
            hl_rhs2_type = hl_rhs2.ctype(astree.ctyper)

            if hl_rhs1_type is None and hl_rhs2_type is None:
                chklogger.logger.error(
                    "Unable to lift pointer arithmetic without type for "
                    + "%s at address %s",
                    str(rhs3), iaddr)
                return astree.mk_temp_lval_expression()

            if hl_rhs2_type is not None and hl_rhs2_type.is_pointer:
                rhs2tgttyp = cast(AST.ASTTypPtr, hl_rhs2_type).tgttyp
                tgttypsize = astree.type_size_in_bytes(rhs2tgttyp)
                if tgttypsize is None:
                    chklogger.logger.warning(
                        "Unable to lift pointer arithmetic without size for "
                        + "%s at address %s; set type size to 1",
                        str(hl_rhs2_type), iaddr)
                    # return astree.mk_temp_lval_expression()
                    tgttypsize = 1

                if tgttypsize == 1:
                    return XU.xxpr_to_ast_def_expr(rhs3, xdata, iaddr, astree)

                if hl_rhs1.is_integer_constant:
                    addend = cast(AST.ASTIntegerConstant, hl_rhs1).cvalue
                    addend = addend // tgttypsize
                    astaddend: AST.ASTExpr = astree.mk_integer_constant(addend)
                    annotations.append("scaled by " + str(tgttypsize))
                    return astree.mk_binary_op("plus", hl_rhs2, astaddend)

                scale = astree.mk_integer_constant(tgttypsize)
                scaled = astree.mk_binary_op("div", hl_rhs1, scale)
                return astree.mk_binary_op("plus", hl_rhs2, scaled)

            if hl_rhs1_type is not None and hl_rhs1_type.is_pointer:
                rhs1tgttyp = cast(AST.ASTTypPtr, hl_rhs1_type).tgttyp
                tgttypsize = astree.type_size_in_bytes(rhs1tgttyp)
                if tgttypsize is None:
                    chklogger.logger.error(
                        "Unable to lift pointer arithmetic without size for "
                        + "%s at address %s",
                        str(hl_rhs1_type), iaddr)
                    return astree.mk_temp_lval_expression()

                if hl_rhs1.is_ast_startof:
                    arraylval = cast(AST.ASTStartOf, hl_rhs1).lval
                    arrayvinfo = cast(AST.ASTVariable, arraylval.lhost).varinfo
                    if tgttypsize == 1:
                        scaled = hl_rhs2
                    else:
                        scale = astree.mk_integer_constant(tgttypsize)
                        scaled = astree.mk_binary_op("div", hl_rhs2, scale)

                    offset = astree.mk_expr_index_offset(scaled)
                    offsetlval = astree.mk_vinfo_lval(arrayvinfo, offset)
                    return astree.mk_address_of(offsetlval)

                if tgttypsize == 1:
                    return XU.xxpr_to_ast_def_expr(rhs3, xdata, iaddr, astree)

                if hl_rhs2.is_integer_constant:
                    addend = cast(AST.ASTIntegerConstant, hl_rhs2).cvalue
                    addend = addend // tgttypsize
                    astaddend = astree.mk_integer_constant(addend)
                    annotations.append("scaled by " + str(tgttypsize))
                    return astree.mk_binary_op("plus", hl_rhs1, astaddend)

                scale = astree.mk_integer_constant(tgttypsize)
                scaled = astree.mk_binary_op("div", hl_rhs2, scale)
                return astree.mk_binary_op("plus", hl_rhs1, scaled)

            if hl_rhs2_type is None:
                chklogger.logger.error(
                    "Unable to lift pointer arithmetic without type for "
                    + "%s at address %s",
                    str(rhs2), iaddr)
                return astree.mk_temp_lval_expression()

            chklogger.logger.error(
                "Second operand pointer variable not yet supported for %s at "
                + "address %s",
                str(rhs3), iaddr)
            return astree.mk_temp_lval_expression()


        # resulting expression is a stack address
        if (
                (str(rrhs1) == "SP" or rrhs1.is_stack_address)
                and rhs3.is_stack_address):
            annotations.append("stack address")
            rhs3 = cast("XprCompound", rhs3)
            stackoffset = rhs3.stack_address_offset()
            rhslval = astree.mk_stack_variable_lval(stackoffset)
            hl_rhs: AST.ASTExpr = astree.mk_address_of(rhslval)

        # resulting expression is a pc-relative address
        elif str(rrhs1) == "PC" or str(rhs2) == "PC":
            annotations.append("PC-relative")
            if rhs3.is_int_constant:
                rhsexpr = XU.xxpr_to_ast_def_expr(rhs3, xdata, iaddr, astree)
                rhsval = cast("XprConstant", rhs3).intvalue
                if rhs3.is_string_reference:
                    saddr = hex(rhsval)
                    cstr = rhs3.constant.string_reference()
                    hl_rhs = astree.mk_string_constant(
                        rhsexpr, cstr, saddr)
                else:
                    hl_rhs = astree.mk_global_address_constant(
                        rhsval, rhsexpr)
            else:
                hl_rhs = XU.xxpr_to_ast_def_expr(rhs3, xdata, iaddr, astree)

        elif rhs3.is_addressof_var:
            hl_rhs = XU.xxpr_to_ast_def_expr(rhs3, xdata, iaddr, astree)
            if rhs3.is_constant_expression:
                astree.set_ssa_value(str(hl_lhs), hl_rhs)

        elif (hl_lhs_type is not None and hl_lhs_type.is_pointer):
            hl_rhs = pointer_arithmetic_expr()
            if rhs3.is_constant_expression:
                astree.set_ssa_value(str(hl_lhs), hl_rhs)

        else:
            hl_rhs = XU.xxpr_to_ast_def_expr(rhs3, xdata, iaddr, astree)

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

        return ([hl_assign], [ll_assign])
