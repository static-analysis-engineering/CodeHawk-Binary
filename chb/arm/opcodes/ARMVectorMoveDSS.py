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
    from chb.arm.ARMVfpDatatype import ARMVfpDatatype


@armregistry.register_tag("VMOVDSS", ARMOpcode)
class ARMVectorMoveDSS(ARMOpcode):
    """Copies two words from two ARM core registers into a doubleword ext. register.

    VMOV<c> <Dm>, <Rt>, <Rt2>

    tags[1]: <c>
    args[0]]: index of vfp-datatype in armdictionary (not used)
    args[1]: index of destination in armdictionary
    args[2]: index of first source in armdictionary
    args[3]: index of second srouce in armdictionary (optional)

    xdata format:
    -------------
    vars[0]: destination operand
    xprs[0]: first source operand
    xprs[1]: second source operand
    xprs[2]: first source operand rewritten
    xprs[3]: second source operand rewritten
    rdefs[0]: reaching definitions of first source operand
    rdefs[1]: reaching definitions of second source operand
    uses[0]: usedefs of destination
    useshigh[0]: usedefs of destination in high-level expressions
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
        lhs = str(xdata.vars[0])
        rhs1 = str(xdata.xprs[2])
        rhs2 = str(xdata.xprs[3])
        return (lhs + " := " + rhs1 + ":" + rhs2)

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VMOV"]

        lhs = xdata.vars[0]
        rhs1 = xdata.xprs[2]
        rhs2 = xdata.xprs[3]
        rdefs1 = xdata.reachingdefs[0]
        rdefs2 = xdata.reachingdefs[1]
        defuses = xdata.defuses[0]
        defuseshigh = xdata.defuseshigh[0]

        (ll_lhs, _, _) = self.opargs[1].ast_lvalue(astree)
        (ll_rhs1, _, _) = self.opargs[2].ast_rvalue(astree)
        (ll_rhs2, _, _) = self.opargs[3].ast_rvalue(astree)
        ll_rhsx = astree.mk_binary_op("lsl", ll_rhs2, astree.mk_integer_constant(32))
        ll_rhs = astree.mk_binary_op("plus", ll_rhs1, ll_rhsx)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        hl_rhss1 = XU.xxpr_to_ast_def_exprs(rhs1, xdata, iaddr, astree)
        hl_rhss2 = XU.xxpr_to_ast_def_exprs(rhs2, xdata, iaddr, astree)

        if len(hl_lhss) == 1 and len(hl_rhss1) == 1 and len(hl_rhss2) == 1:
            hl_lhs = hl_lhss[0]
            hl_rhs1 = hl_rhss1[0]
            hl_rhs2 = hl_rhss2[0]

            hl_rhsx = astree.mk_binary_op("lsl", hl_rhs2, astree.mk_integer_constant(32))
            hl_rhs = astree.mk_binary_op("plus", hl_rhs1, hl_rhsx)

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
            astree.add_expr_reachingdefs(ll_rhs, [rdefs1, rdefs2])
            astree.add_expr_reachingdefs(hl_rhs1, [rdefs1])
            astree.add_expr_reachingdefs(hl_rhs2, [rdefs2])
            astree.add_lval_defuses(hl_lhs, defuses)
            astree.add_lval_defuses_high(hl_lhs, defuseshigh)

            return ([hl_assign], [ll_assign])

        else:
            raise UF.CHBError(
                "VectorMove (VMOV): multiple lval/expressions in ast")
