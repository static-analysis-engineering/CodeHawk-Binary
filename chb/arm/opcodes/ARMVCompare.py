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

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMVfpDatatype import ARMVfpDatatype


@armregistry.register_tag("VCMPE", ARMOpcode)
@armregistry.register_tag("VCMP", ARMOpcode)
class ARMVCompare(ARMOpcode):
    """Compares two floating-point numbers.

    VCMP{E}<c>.F64 <Dd> <Dm>
    VCMP{E}<c>.F32 <Sd> <Sm>

    VCMP{E}<c>.F64 <Dd>, #0.0
    VCMP{E}<c>.F32 <Sd>, #0.0

    tags[1]: <c>
    args[0]: nan (1 = raise Invalid Operation when one of the operands is NaN)
    args[1]: index of destination datatype in armdictionary
    args[2]: index of d in armdictionary
    args[3]: index of m in armdictionary

    xdata format: axxxxrr
    ---------------------
    xprs[0]: xd
    xprs[1]: xm
    xprs[2]: xd (simplified)
    xprs[3]: xm (simplified)
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "VCompare")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [2, 3]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        vfpdt = str(self.vfp_datatype)
        return cc + vfpdt

    @property
    def vfp_datatype(self) -> "ARMVfpDatatype":
        return self.armd.arm_vfp_datatype(self.args[1])

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [2, 3]]

    def annotation(self, xdata: InstrXData) -> str:
        rhs1 = str(xdata.xprs[2])
        rhs2 = str(xdata.xprs[3])
        comparison = "compare " + rhs1 + " and " + rhs2
        return comparison

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VCMPE"]

        rhs1 = xdata.xprs[2]
        rhs2 = xdata.xprs[3]
        rdefs = xdata.reachingdefs

        (ll_rhs1, _, _) = self.opargs[0].ast_rvalue(astree)
        (ll_rhs2, _, _) = self.opargs[1].ast_rvalue(astree)
        ll_expr = astree.mk_binary_op("minus", ll_rhs1, ll_rhs2)
        ll_assign = astree.mk_assign(
            astree.ignoredlhs,
            ll_expr,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        hl_rhss1 = XU.xxpr_to_ast_def_exprs(rhs1, xdata, iaddr, astree)
        hl_rhss2 = XU.xxpr_to_ast_def_exprs(rhs2, xdata, iaddr, astree)
        hl_rhs = astree.mk_binary_op("minus", hl_rhss1[0], hl_rhss2[0])

        hl_assign = astree.mk_assign(
            astree.ignoredlhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_expr)
        astree.add_expr_reachingdefs(ll_rhs1, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_rhs2, [rdefs[1]])
        astree.add_expr_reachingdefs(hl_rhs, rdefs[2:])

        return ([hl_assign], [ll_assign])
