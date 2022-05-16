# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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

from typing import cast, List, TYPE_CHECKING

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
    def writeback(self) -> bool:
        return self.args[0] == 1

    def mnemonic_extension(self) -> str:
        wb = "S" if self.writeback else ""
        cc = ARMOpcode.mnemonic_extension(self)
        return wb + cc

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxxxx .

        vars[0]: lhs (Rd)
        xprs[0]: rhs1 (Rn)
        xprs[1]: rhs2 (Rm{..})
        xprs[2]: rhs1 + rhs2 (syntactic)
        xprs[3]: rhs1 + rhs2 (simplified)
        """

        lhs = str(xdata.vars[0])
        result = xdata.xprs[2]
        rresult = xdata.xprs[3]
        xresult = simplify_result(xdata.args[3], xdata.args[4], result, rresult)
        return lhs + " := " + xresult

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

    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        """Create one register-to-register assignment."""

        annotations: List[str] = [iaddr, "ADD"]

        # there are no versions of ADD with write-back arguments
        (lhs, _, _) = self.operands[0].ast_lvalue(astree)
        (op1, _, _) = self.operands[1].ast_rvalue(astree)
        (op2, _, _) = self.operands[2].ast_rvalue(astree)

        binop = astree.mk_binary_op("plus", op1, op2)
        assign = astree.mk_assign(lhs, binop, annotations=annotations)
        astree.add_instruction_span(assign.instrid, iaddr, bytestring)
        return [assign]

    def ast(self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        """Create one or more register-to-register assignments.

        There may be more than one assignment if the source expression
        and/or the destination register has a type smaller than 4.
        """
        lhs = xdata.vars[0]
        rhs1 = str(xdata.xprs[0])
        rhs2 = xdata.xprs[1]
        rhs3 = xdata.xprs[3]

        # if lhs == "SP" and rhs1 == "SP" and rhs2.is_constant:
        #    return []

        annotations: List[str] = [iaddr, "ADD"]

        lhsasts = XU.xvariable_to_ast_lvals(lhs, astree)
        if len(lhsasts) != 1:
            raise UF.CHBError("ARMAdd: multiple lvals in ast")

        lhsast = lhsasts[0]

        if str(lhs) == "PC":
            astree.add_note(iaddr + ": ADD instruction sets PC")

        # resulting expression is a stack address
        if rhs1 == "SP" and rhs3.is_stack_address:
            annotations.append("stack address")
            rhs3 = cast("XprCompound", rhs3)
            stackoffset = rhs3.stack_address_offset()
            rhslval = astree.mk_stack_variable_lval(stackoffset)
            rhsast: AST.ASTExpr = astree.mk_address_of(rhslval)

        # resulting expression is a pc-relative address
        elif rhs1 == "PC" or str(rhs2) == "PC":
            annotations.append("PC-relative")
            if rhs3.is_int_constant:
                rhsval = cast("XprConstant", rhs3).intvalue
                rhsast = astree.mk_integer_constant(rhsval)
            else:
                rhsasts = XU.xxpr_to_ast_exprs(rhs3, astree)
                if len(rhsasts) == 1:
                    rhsast = rhsasts[0]
                else:
                    raise UF.CHBError(
                        "ARMAdd: multiple expressions in ast")

        else:
            return self.assembly_ast(astree, iaddr, bytestring, xdata)

        assign = astree.mk_assign(lhsast, rhsast, annotations=annotations)
        astree.add_instruction_span(assign.instrid, iaddr, bytestring)
        return [assign]
