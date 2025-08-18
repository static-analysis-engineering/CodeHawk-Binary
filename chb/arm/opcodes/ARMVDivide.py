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

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMVfpDatatype import ARMVfpDatatype
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XprCompound, XprConstant, XXpr


class ARMVDivideXData(ARMOpcodeXData):
    """
    Data format:
    - variables:
    0: vdst

    - expressions:
    0: xsrc1
    1: xsrc2
    2: rxsrc1
    3: rxsrc2
    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vdst(self) -> "XVariable":
        return self.var(0, "vdst")

    @property
    def xsrc1(self) -> "XXpr":
        return self.xpr(0, "xsrc1")

    @property
    def xsrc2(self) -> "XXpr":
        return self.xpr(1, "xsrc2")

    @property
    def rxsrc1(self) -> "XXpr":
        return self.xpr(2, "rxsrc1")

    @property
    def rxsrc2(self) -> "XXpr":
        return self.xpr(3, "rxsrc2")

    @property
    def annotation(self) -> str:
        lhs = str(self.vdst)
        rhs1 = str(self.rxsrc1)
        rhs2 = str(self.rxsrc2)
        assign = lhs + " := " + rhs1 + " / " + rhs2
        return self.add_instruction_condition(assign)


@armregistry.register_tag("VDIV", ARMOpcode)
class ARMVDivide(ARMOpcode):
    """Divides one floating point value by another floating point value.

    VDIV<c>.F64 <Dd>, <Dn>, <Dm>
    VDIV<c>.F32 <Sd>, <Sn>, <Sm>

    tags[1]: <c>
    args[0]: index of datatype in armdictionary
    args[1]: index of dd in armdictionary
    args[2]: index of dn in armdictionary
    args[3]: index of dm in armdictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "VDivide")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        vfpdt = str(self.vfp_datatype)
        return cc + vfpdt

    @property
    def vfp_datatype(self) -> "ARMVfpDatatype":
        return self.armd.arm_vfp_datatype(self.args[0])

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMVDivideXData(xdata)
        return xd.annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VDIV"]

        # low-level assignment

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs1, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_rhs2, _, _) = self.opargs[2].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("div", ll_rhs1, ll_rhs2)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        rdefs = xdata.reachingdefs

        astree.add_expr_reachingdefs(ll_rhs1, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_rhs2, [rdefs[1]])

        # high-level assignment

        xd = ARMVDivideXData(xdata)

        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        lhs = xd.vdst
        rhs1 = xd.rxsrc1
        rhs2 = xd.rxsrc2

        hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)
        hl_rhs1 = XU.xxpr_to_ast_def_expr(rhs1, xdata, iaddr, astree)
        hl_rhs2 = XU.xxpr_to_ast_def_expr(rhs2, xdata, iaddr, astree)
        hl_rhs = astree.mk_binary_op("div", hl_rhs1, hl_rhs2)

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(hl_rhs, rdefs[2:])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        return ([hl_assign], [ll_assign])
