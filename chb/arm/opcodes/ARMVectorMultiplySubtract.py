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

from chb.invariants.XXpr import XXpr, XprConstant
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMVfpDatatype import ARMVfpDatatype
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XprCompound, XprConstant, XXpr


class ARMVectorMultiplySubtractXData(ARMOpcodeXData):
    """
    Data format:
    - variables:
    0: vdst

    - expressions:
    0: xsrc1
    1: xsrc2
    2: xdst
    3: rxsrc1
    4: rxsrc2
    5: rxdst
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
    def xdst(self) -> "XXpr":
        return self.xpr(2, "xdst")

    @property
    def rxsrc1(self) -> "XXpr":
        return self.xpr(3, "rxsrc1")

    @property
    def rxsrc2(self) -> "XXpr":
        return self.xpr(4, "rxsrc2")

    @property
    def rxdst(self) -> "XXpr":
        return self.xpr(5, "rxdst")



@armregistry.register_tag("VMLS", ARMOpcode)
class ARMVectorMultiplySubtract(ARMOpcode):
    """Multiplies corresponding elements in a vector and subtracts from dst.

    VMLS<c>.F32 <Qd>, <Qn>, <Qm>
    VMLS<c>.F32 <Dd>, <Dn>, <Dm>

    VMLS<c>.<dt> <Qd>, <Qn>, <Dm[x]>
    VMLS<c>.<dt> <Dd>, <Dn>, <Dm[x]>

    tags[1]: <c>
    args[0]: index of datatype in armdictionary
    args[1]: index of qd in armdictionary
    args[2]: index of qn in armdictionary
    args[3]: index of qm/dm[x] in armdictionary
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "VectorMultiplySubtract")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        vfpdt = str(self.vfp_datatype)
        return cc + vfpdt

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]


    @property
    def vfp_datatype(self) -> "ARMVfpDatatype":
        return self.armd.arm_vfp_datatype(self.args[0])

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMVectorMultiplySubtractXData(xdata)
        lhs = str(xd.vdst)
        rhs1 = str(xd.rxsrc1)
        rhs2 = str(xd.rxsrc2)
        rhsd = str(xd.rxdst)
        return lhs + " := " + rhsd + " - (" + rhs1 + " * " + rhs2 + ")"

    def _unpack_imm32(self, x: XXpr) -> float:
        # from StackOverflow:
        # https://stackoverflow.com/questions/33483846/how-to-convert-32-bit-binary-to-float

        ci = cast(XprConstant, x).intvalue
        return struct.unpack('f', struct.pack('I', ci))[0]

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VMLS"]

        # low-level assignment

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs1, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_rhs2, _, _) = self.opargs[2].ast_rvalue(astree)
        (ll_rhsd, _, _) = self.opargs[0].ast_rvalue(astree)
        ll_mul = astree.mk_binary_op("mult", ll_rhs1, ll_rhs2)
        ll_rhs = astree.mk_binary_op("minus", ll_rhsd, ll_mul)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignment

        xd = ARMVectorMultiplySubtractXData(xdata)

        lhs = xd.vdst
        rhs1 = xd.rxsrc1
        rhs2 = xd.rxsrc2
        rhsd = xd.rxdst
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)

        if rhs1.is_int_constant:
            f = self._unpack_imm32(rhs1)
            hl_rhs1: AST.ASTExpr = astree.mk_float_constant(f)
        else:
            hl_rhs1 = XU.xxpr_to_ast_def_expr(rhs1, xdata, iaddr, astree)

        if rhs2.is_int_constant:
            f = self._unpack_imm32(rhs2)
            hl_rhs2: AST.ASTExpr = astree.mk_float_constant(f)
        else:
            hl_rhs2 = XU.xxpr_to_ast_def_expr(rhs2, xdata, iaddr, astree)

        if rhsd.is_int_constant:
            f = self._unpack_imm32(rhsd)
            hl_rhsd: AST.ASTExpr = astree.mk_float_constant(f)
        else:
            hl_rhsd = XU.xxpr_to_ast_def_expr(rhsd, xdata, iaddr, astree)

        hl_sub = astree.mk_binary_op("mult", hl_rhs1, hl_rhs2)
        hl_rhs = astree.mk_binary_op("minus", hl_rhsd, hl_sub)

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs1, ll_rhs1)
        astree.add_expr_mapping(hl_rhs2, ll_rhs2)
        astree.add_expr_mapping(hl_rhsd, ll_rhsd)
        astree.add_expr_reachingdefs(hl_rhs1, [rdefs[0]])
        astree.add_expr_reachingdefs(hl_rhs2, [rdefs[1]])
        astree.add_expr_reachingdefs(hl_rhsd, [rdefs[2]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        return ([hl_assign], [ll_assign])
