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
from codecs import decode
import struct

from typing import cast, List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

from chb.invariants.XXpr import XprConstant
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("VMOV", ARMOpcode)
class ARMVectorMove(ARMOpcode):
    """Transfers a floating point register to a core register or v.v.

    VMOV<c>.<dt> <Sn> <Rt> or VMOV<c> <Rt> <Sn> or VMOV<c> <S/Qn> #<imm>

    tags[1]: <c>
    tags[2]: <dt>
    args[0]: index of op1 in armdictionary
    args[1]: index of op2 in armdictionary
    args[2]: index of op3 in armdictionary (optional)
    args[3]: index of op4 in armdictionary (optional)
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)

    @property
    def operands(self) -> List[ARMOperand]:
        return [
            self.armd.arm_operand(i)
            for i in self.args[1:len(self.args)]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [
            self.armd.arm_operand(i)
            for i in self.args[1:len(self.args)]]

    def annotation(self, xdata: InstrXData) -> str:
        if len(xdata.vars) == 1 and len(xdata.xprs) == 1:
            return str(xdata.vars[0]) + " := " + str(xdata.xprs[0])
        else:
            return "pending"

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VMOV"]

        lhs = xdata.vars[0]
        rhs = xdata.xprs[0]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs, _, _) = self.opargs[1].ast_rvalue(astree)
        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)

        if rhs.is_int_constant and str(lhs).startswith("S"):
            # 32-bit floating-point constant
            rhs = cast(XprConstant, rhs)
            rhsvalue = rhs.intvalue

            # from StackOverflow:
            # https://stackoverflow.com/questions/33483846/how-to-convert-32-bit-binary-to-float

            f = struct.unpack('f', struct.pack('I', rhsvalue))[0]
            hl_rhss: List[AST.ASTExpr] = [astree.mk_float_constant(f)]

        else:
            hl_rhss = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)

        if len(hl_lhss) == 1 and len(hl_rhss) == 1:
            hl_lhs = hl_lhss[0]
            hl_rhs = hl_rhss[0]

            if str(hl_lhs).startswith("S") and str(ll_rhs).startswith("R"):
                hl_rhs = astree.mk_cast_expr(astree.astree.float_type, hl_rhs)
            hl_assign = astree.mk_assign(
                hl_lhs,
                hl_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)

            astree.add_reg_definition(iaddr, hl_lhs, hl_rhs)
            astree.add_instr_mapping(hl_assign, ll_assign)
            astree.add_instr_address(hl_assign, [iaddr])
            astree.add_expr_mapping(hl_rhs, ll_rhs)
            astree.add_lval_mapping(hl_lhs, ll_lhs)
            astree.add_expr_reachingdefs(ll_rhs, [rdefs[0]])
            astree.add_expr_reachingdefs(hl_rhs, rdefs[1:])
            astree.add_lval_defuses(hl_lhs, defuses[0])
            astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

            return ([hl_assign], [ll_assign])

        else:
            raise UF.CHBError(
                "VectorMove (VMOV): multiple lval/expressions in ast")
