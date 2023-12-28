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

from typing import List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMVfpDatatype import ARMVfpDatatype


@armregistry.register_tag("VCVTR", ARMOpcode)
@armregistry.register_tag("VCVT", ARMOpcode)
class ARMVectorConvert(ARMOpcode):
    """Converts between floating point and integer.

    VCVT<c>.<Td>.<Tm> <Qd>, <Qm>
    VCVT<c>.<Td>.<Tm> <Dd>, <Dm>

    VCVT{R}<c>.S32.F64 <Sd>, <Dm>
    VCVT{R}<c>.S32.F32 <Sd>, <Sm>
    VCVT{R}<c>.U32.F64 <Sd>, <Dm>
    VCVT{R}<c>.U32.F32 <Sd>, <Sm>
    VCVT{R}<c>.F64.<Tm> <Dd>, <Sm>
    VCVT{R}<c>.F32.<Tm> <Sd>, <Sm>

    VCVT<c>.<Td>.<Tm> <Qd>, <Qm>, #<fbits>
    VCVT<c>.<Td>.<Tm> <Dd>, <Dm>, #<fbits>

    VCVT<c>.<Td>.F64 <Dd>, <Dd>, #<fbits>
    VCVT<c>.<Td>.F32 <Sd>, <Sd>, #<fbits>
    VCVT<c>.F64.<Td> <Dd>, <Dd>, #<fbits>
    VCVT<c>.F32.<Td> <Sd>, <Sd>, #<fbits>

    VCVT<c>.F64.F32 <Dd>, <Sm>
    VCVT<c>.F32.F64 <Sd>, <Dm>

    VCVT<c>.F32.F16 <Qd>, <Dm>
    VCVT<c>.F16.F32 <Dd>, <Qm>

    tags[1]: <c>
    args[0]: round (0 or 1)
    args[1]: fixed-point (0 or 1)
    args[2]: index of destination datatype in armdictionary
    args[3]: index of source datatype in armdictionary
    args[4]: index of destination in armdictionary
    args[5]: index of source in armdictionary
    args[6]: fbits
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 7, "VectorConvert")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [4, 5]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        vfpdt1 = str(self.vfp_datatype1)
        vfpdt2 = str(self.vfp_datatype2)
        return cc + vfpdt1 + vfpdt2

    @property
    def vfp_datatype1(self) -> "ARMVfpDatatype":
        return self.armd.arm_vfp_datatype(self.args[2])

    @property
    def vfp_datatype2(self) -> "ARMVfpDatatype":
        return self.armd.arm_vfp_datatype(self.args[3])

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [4, 5]]

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxx .

        vars[0]: lhs
        xprs[0]: rhs
        xprs[1]: rhs rewritten
        """

        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[1])
        return lhs + " := " + rhs

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VCVT"]

        lhs = xdata.vars[0]
        rhs = xdata.xprs[1]
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
        hl_rhss = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)
        if len(hl_lhss) == 1 and len(hl_rhss) == 1:
            hl_lhs = hl_lhss[0]
            hl_rhs = hl_rhss[0]
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
                "VectorConvert (VCVT): multiple lval/expressions in ast")
