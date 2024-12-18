# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    import chb.arm.ARMDictionary
    from chb.invariants.XXpr import XprCompound, XprConstant


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

    xdata format: a:vxxxxrrdh
    -------------------------
    vars[0]: lhs (Rd)
    xprs[0]: rhs1 (Rn)
    xprs[1]: rhs2 (Rm)
    xprs[2]: rhs1 + rhs2
    xprs[3]: rhs1 + rhs2 (simplified)
    xprs[4]: rhs1 (simplified)
    xprs[5]: rhs2 (simplified)
    rdefs[0]: rhs1
    rdefs[1]: rhs2
    rdefs[2:..]: reaching definitions for simplified result expression
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
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
        lhs = str(xdata.vars[0])
        result = xdata.xprs[2]
        rresult = xdata.xprs[3]
        xresult = simplify_result(xdata.args[3], xdata.args[4], result, rresult)
        assignment = lhs + " := " + xresult
        if xdata.has_unknown_instruction_condition():
            return "if ? then " + assignment
        elif xdata.has_instruction_condition():
            c = str(xdata.xprs[1])
            return "if " + c + " then " + assignment
        else:
            return assignment

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

        lhs = xdata.vars[0]
        rhs1 = xdata.xprs[0]
        rhs2 = xdata.xprs[1]
        rhs3 = xdata.xprs[3]
        rrhs1 = xdata.xprs[4]
        rrhs2 = xdata.xprs[5]

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
