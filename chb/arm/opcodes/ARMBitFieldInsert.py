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

import chb.arm.ARMPseudoCode as APC

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMBitFieldInsertXData(ARMOpcodeXData):
    """BFI <rd> <rn>"""

    def __init__(self, xdata: InstrXData, lsb: int, width: int) -> None:
        ARMOpcodeXData.__init__(self, xdata)
        self._lsb = lsb
        self._width = width

    @property
    def lsb(self) -> int:
        return self._lsb

    @property
    def width(self) -> int:
        return self._width

    @property
    def vrd(self) -> "XVariable":
        return self.var(0, "vrd")

    @property
    def xrd(self) -> "XXpr":
        return self.xpr(0, "xrd")

    @property
    def xrn(self) -> "XXpr":
        return self.xpr(1, "xrn")

    @property
    def annotation(self) -> str:
        lhs = str(self.vrd)
        rhs1 = str(self.xrd)
        rhs2 = str(self.xrn)
        assign = (
            lhs
            + " := bit-field-insert("
            + rhs1
            + ", "
            + rhs2
            + ", lsb:"
            + str(self.lsb)
            + ", width:"
            + str(self.width))
        return self.add_instruction_condition(assign)


@armregistry.register_tag("BFI", ARMOpcode)
class ARMBitFieldInsert(ARMOpcode):
    """Copies bits from one register to another register

    BFI <Rd>, <Rn>, #<lsb>, #<width>

    tags[1]: <c>
    args[0]: index of Rd in armdictionary
    args[1]: index of Rn in armdictionary
    args[2]: lsb position
    args[3]: width
    args[4]: msb position

    xdata format: a:vxxrrdh
    ------------------------
    vars[0]: lhs
    xprs[0]: rhs1
    xprs[1]: rhs2
    rdefs[0]: rhs1
    rdefs[1]: rhs2
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "BitFieldInsert")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1]]

    @property
    def operandstring(self) -> str:
        ops = ", ".join(str(op) for op in self.operands)
        pos = ", #" + str(self.args[2]) + ", #" + str(self.args[3])
        return ops + pos

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    @property
    def lsb(self) -> int:
        return self.args[1]

    @property
    def width(self) -> int:
        return self.args[2]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMBitFieldInsertXData(xdata, self.lsb, self.width)
        return xd.annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "BFI"]

        if self.width == 0:
            nopinstr = astree.mk_nop_instruction(
                "BFI (width = 0)",
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            astree.add_instr_address(nopinstr, [iaddr])

            return ([], [nopinstr])

        xd = ARMBitFieldInsertXData(xdata, self.lsb, self.width)

        lhs = xd.vrd
        rhs1 = xd.xrd
        rhs2 = xd.xrn
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        (ll_lhs, _, _) = self.operands[0].ast_lvalue(astree)
        (ll_op1, _, _) = self.operands[0].ast_rvalue(astree)
        (ll_op2, _, _) = self.operands[0].ast_rvalue(astree)

        mask1 = int("1" * self.width, 2)
        mask1const = astree.mk_integer_constant(mask1)
        ll_rhs2 = astree.mk_binary_op("band", ll_op2, mask1const)
        mask2 = APC.bitfieldmask(32, self.lsb, self.width)
        mask2const = astree.mk_integer_constant(mask2)
        ll_rhs1 = astree.mk_binary_op("band", ll_op1, mask2const)
        ll_rhs = astree.mk_binary_op("plus", ll_rhs1, ll_rhs2)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        lhsasts = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        if len(lhsasts) == 0:
            raise UF.CHBError("BitFieldInsert (BFI): no lval found")

        if len(lhsasts) > 1:
            raise UF.CHBError(
                "BitFieldInsert (BFI): multiple lvals found: "
                + ", ".join(str(v) for v in lhsasts))

        hl_lhs = lhsasts[0]

        rhs1asts = XU.xxpr_to_ast_def_exprs(rhs1, xdata, iaddr, astree)
        if len(rhs1asts) == 0:
            raise UF.CHBError("BitFieldInsert (BFI): no rhs1 value found")

        if len(rhs1asts) > 1:
            raise UF.CHBError(
                "BitFieldInsert (BFI): multiple rhs1 values found: "
                + ", ".join(str(v) for v in rhs1asts))

        hl_prhs1 = rhs1asts[0]

        rhs2asts = XU.xxpr_to_ast_def_exprs(rhs2, xdata, iaddr, astree)
        if len(rhs2asts) == 0:
            raise UF.CHBError("BitFieldInsert (BFI): no rhs2 value found")

        if len(rhs2asts) > 1:
            raise UF.CHBError(
                "BitFieldInsert (BFI): multiple rhs2 values found: "
                + ", ".join(str(v) for v in rhs2asts))

        hl_prhs2 = rhs2asts[0]

        hl_rhs2 = astree.mk_binary_op("band", hl_prhs2, mask1const)
        hl_rhs1 = astree.mk_binary_op("band", hl_prhs1, mask2const)
        hl_rhs = astree.mk_binary_op("plus", hl_rhs1, hl_rhs2)

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_reg_definition(iaddr, hl_lhs, hl_rhs)
        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_prhs1, ll_op1)
        astree.add_expr_mapping(hl_rhs1, ll_rhs1)
        astree.add_expr_mapping(hl_rhs2, ll_rhs2)
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(ll_op1, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_op2, [rdefs[1]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        return ([hl_assign], [ll_assign])
