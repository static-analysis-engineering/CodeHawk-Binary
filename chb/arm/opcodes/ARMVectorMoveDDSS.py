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
from codecs import decode
import struct

from typing import cast, List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

from chb.invariants.XXpr import XprConstant
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMVfpDatatype import ARMVfpDatatype
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XprCompound, XprConstant, XXpr


class ARMVectorMoveDDSSXData(ARMOpcodeXData):
    """
    Data format:
    - variables:
    0: vdst1
    1: vdst2
    2: vddst

    - expressions:
    0: xsrc1
    1: xsrc2
    2: xssrc
    3: rxsrc1
    4: rxsrc2
    5: rxssrc
    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vdst1(self) -> "XVariable":
        return self.var(0, "vdst1")

    @property
    def vdst2(self) -> "XVariable":
        return self.var(1, "vdst2")

    @property
    def vdddst(self) -> "XVariable":
        return self.var(2, "vddst")

    @property
    def xsrc1(self) -> "XXpr":
        return self.xpr(0, "xsrc1")

    @property
    def xsrc2(self) -> "XXpr":
        return self.xpr(1, "xsrc2")

    @property
    def xssrc(self) -> "XXpr":
        return self.xpr(2, "xssrc")

    @property
    def rxsrc1(self) -> "XXpr":
        return self.xpr(3, "rxsrc1")

    @property
    def rxsrc2(self) -> "XXpr":
        return self.xpr(4, "rxsrc2")

    @property
    def rxssrc(self) -> "XXpr":
        return self.xpr(5, "rxssrc")

    @property
    def annotation(self) -> str:
        lhs1 = str(self.vdst1)
        lhs2 = str(self.vdst2)
        rhs1 = str(self.rxssrc)
        rhs2 = str(self.rxsrc2)
        assign = lhs1 + " := " + rhs1 + "; " + lhs2 + " := " + rhs2
        return self.add_instruction_condition(assign)


@armregistry.register_tag("VMOVDDSS", ARMOpcode)
class ARMVectorMoveDDSS(ARMOpcode):
    """Transfers two single-precision fp registers to two ARM core registers and v.v.

    VMOV<c> <Sm>, <Sm1>, <Rt>, <Rt2>
    VMOV<c> <Rt>, <Rt2>, <Sm>, <Sm1>

    tags[1]: <c>
    args[0]: index of vfp-data type in armdictionary (not used)
    args[1]: index of first destination in armdictionary
    args[2]: index of second destination in armdictionary
    args[3]: index of first source in armdictionary
    args[4]: index of second source in armdictionary

    xdata format:
    -------------
    vars[0]: first destination
    vars[1]: second destination
    xprs[0]: first source
    xprs[1]: second source
    xprs[2]: first source rewritten
    xprs[3]: second source rewritten
    rdefs[0]: reaching definitions for first source
    rdefs[1]: reaching definitions for second source
    uses[0]: uses of first destination
    uses[1]: uses of second destination
    useshigh[0]: uses of first destination in high-level expressions
    useshigh[1]: uses of second destination in high-level expressions
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)

    @property
    def mnemonic(self) -> str:
        return "VMOV"

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        vfpdt = str(self.vfp_datatype)
        return cc + vfpdt

    @property
    def vfp_datatype(self) -> "ARMVfpDatatype":
        return self.armd.arm_vfp_datatype(self.args[0])

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMVectorMoveDDSSXData(xdata)
        return xd.annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VMOV"]

        lhs1 = xdata.vars[0]
        lhs2 = xdata.vars[1]
        rhs1 = xdata.xprs[2]
        rhs2 = xdata.xprs[3]
        rdefs1 = xdata.reachingdefs[0]
        rdefs2 = xdata.reachingdefs[1]
        defuses1 = xdata.defuses[0]
        defuses2 = xdata.defuses[1]
        defuseshigh1 = xdata.defuseshigh[0]
        defuseshigh2 = xdata.defuseshigh[1]

        (ll_lhs1, _, _) = self.opargs[1].ast_lvalue(astree)
        (ll_lhs2, _, _) = self.opargs[3].ast_lvalue(astree)
        (ll_rhs1, _, _) = self.opargs[2].ast_rvalue(astree)
        (ll_rhs2, _, _) = self.opargs[4].ast_rvalue(astree)

        ll_assign1 = astree.mk_assign(
            ll_lhs1,
            ll_rhs1,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        ll_assign2 = astree.mk_assign(
            ll_lhs2,
            ll_rhs2,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        ll_assigns: List[AST.ASTInstruction] = [ll_assign1, ll_assign2]
        hl_assigns: List[AST.ASTInstruction] = []

        hl_lhss1 = XU.xvariable_to_ast_lvals(lhs1, xdata, astree)
        hl_lhss2 = XU.xvariable_to_ast_lvals(lhs2, xdata, astree)

        hl_rhss1 = XU.xxpr_to_ast_def_exprs(rhs1, xdata, iaddr, astree)
        hl_rhss2 = XU.xxpr_to_ast_def_exprs(rhs2, xdata, iaddr, astree)

        if len(hl_lhss1) == 1 and len(hl_rhss1) == 1:
            hl_lhs1 = hl_lhss1[0]
            hl_rhs1 = hl_rhss1[0]

            if str(hl_lhs1).startswith("S") and str(ll_rhs1).startswith("R"):
                hl_rhs1 = astree.mk_cast_expr(astree.astree.float_type, hl_rhs1)

            hl_assign1 = astree.mk_assign(
                hl_lhs1,
                hl_rhs1,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)

            astree.add_reg_definition(iaddr, hl_lhs1, hl_rhs1)
            astree.add_instr_mapping(hl_assign1, ll_assign1)
            astree.add_instr_address(hl_assign1, [iaddr])
            astree.add_expr_mapping(hl_rhs1, ll_rhs1)
            astree.add_lval_mapping(hl_lhs1, ll_lhs1)
            astree.add_expr_reachingdefs(ll_rhs1, [rdefs1])
            astree.add_lval_defuses(hl_lhs1, defuses1)
            astree.add_lval_defuses_high(hl_lhs1, defuseshigh1)

            hl_assigns.append(hl_assign1)

        if len(hl_lhss2) == 1 and len(hl_rhss2) == 1:
            hl_lhs2 = hl_lhss2[0]
            hl_rhs2 = hl_rhss2[0]

            if str(hl_lhs2).startswith("S") and str(ll_rhs2).startswith("R"):
                hl_rhs2 = astree.mk_cast_expr(astree.astree.float_type, hl_rhs2)

            hl_assign2 = astree.mk_assign(
                hl_lhs2,
                hl_rhs2,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)

            astree.add_reg_definition(iaddr, hl_lhs2, hl_rhs2)
            astree.add_instr_mapping(hl_assign2, ll_assign2)
            astree.add_instr_address(hl_assign2, [iaddr])
            astree.add_expr_mapping(hl_rhs2, ll_rhs2)
            astree.add_lval_mapping(hl_lhs2, ll_lhs2)
            astree.add_expr_reachingdefs(ll_rhs2, [rdefs2])
            # astree.add_expr_reachingdefs(hl_rhs1, [rdefs[1]]
            astree.add_lval_defuses(hl_lhs2, defuses2)
            astree.add_lval_defuses_high(hl_lhs2, defuseshigh2)

            hl_assigns.append(hl_assign2)

        return (ll_assigns, hl_assigns)
