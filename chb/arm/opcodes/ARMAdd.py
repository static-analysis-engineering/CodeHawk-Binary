# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs LLC
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
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

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

        lhs = xdata.vars[0]
        rhs1 = xdata.xprs[0]
        rhs2 = xdata.xprs[1]
        rhs3 = xdata.xprs[3]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        (ll_lhs, _, _) = self.operands[0].ast_lvalue(astree)
        (ll_op1, _, _) = self.operands[1].ast_rvalue(astree)
        (ll_op2, _, _) = self.operands[2].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("plus", ll_op1, ll_op2)

        astree.add_expr_reachingdefs(ll_op1, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_op2, [rdefs[1]])

        hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        if len(hl_lhss) == 0:
            raise UF.CHBError("ADD: no lval found")

        if len(hl_lhss) > 1:
            raise UF.CHBError(
                "ADD: multiple lvals in ast: "
                + ", ".join(str(v) for v in hl_lhss))

        hl_lhs = hl_lhss[0]

        if str(lhs) == "PC":
            astree.add_diagnostic(iaddr + ": ADD instruction sets PC")

        # resulting expression is a stack address
        if str(rhs1) == "SP" and rhs3.is_stack_address:
            annotations.append("stack address")
            rhs3 = cast("XprCompound", rhs3)
            stackoffset = rhs3.stack_address_offset()
            rhslval = astree.mk_stack_variable_lval(stackoffset)
            rhsast: AST.ASTExpr = astree.mk_address_of(rhslval)

        # resulting expression is a pc-relative address
        elif str(rhs1) == "PC" or str(rhs2) == "PC":
            annotations.append("PC-relative")
            if rhs3.is_int_constant:
                rhsexprs = XU.xxpr_to_ast_exprs(rhs3, xdata, astree)
                if len(rhsexprs) == 1:
                    rhsval = cast("XprConstant", rhs3).intvalue
                    rhsast = astree.mk_global_address_constant(rhsval, rhsexprs[0])
                else:
                    raise UF.CHBError(
                        "ADD: multiple expressions in pc-relative expression")
            else:
                rhsasts = XU.xxpr_to_ast_exprs(rhs3, xdata, astree)
                if len(rhsasts) == 1:
                    rhsast = rhsasts[0]
                else:
                    raise UF.CHBError(
                        "ADD: multiple expressions in ast")

        else:
            rhsasts = XU.xxpr_to_ast_def_exprs(rhs3, xdata, iaddr, astree)
            if len(rhsasts) == 1:
                rhsast = rhsasts[0]
            else:
                raise UF.CHBError(
                    "ADD: multiple expressions in ast")

        hl_rhs = rhsast

        hl_rhs = rhsast
        return self.ast_variable_intro(
            astree,
            astree.astree.int_type,
            hl_lhs,
            hl_rhs,
            ll_lhs,
            ll_rhs,
            rdefs[2:],
            rdefs[:2],
            defuses[0],
            defuseshigh[0],
            True,
            iaddr,
            annotations,
            bytestring)
