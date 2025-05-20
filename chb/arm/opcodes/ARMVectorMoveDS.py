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


class ARMVectorMoveDSXData(ARMOpcodeXData):
    """
    Data format:
    - variables:
    0: vdst

    - expressions:
    0: xsrc
    1: rxsrc
    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vdst(self) -> "XVariable":
        return self.var(0, "vdst")

    @property
    def xsrc(self) -> "XXpr":
        return self.xpr(0, "xsrc")

    @property
    def rxsrc(self) -> "XXpr":
        return self.xpr(1, "rxsrc")


@armregistry.register_tag("VMOVDS", ARMOpcode)
class ARMVectorMoveDS(ARMOpcode):
    """Transfers a floating point value/register to a core register or v.v.

    This variant covers the following cases:

    Immediate:
    - VMOV<c>.<dt> <Qd>, #<imm>
    - VMOV<c>.<dt> <Dd>, #<imm>
    - VMOV<c>.F64 <Dd>, #<imm>
    - VMOV<c>.F32 <Sd>, #<imm>

    Register:
    - VMOV<c> <Qd>, <Qm>
    - VMOV<c> <Dd>, <Dm>
    - VMOV<c>.F64 <Dd>, <Dm>
    - VMOV<c>.F32 <Sd>, <Sm>

    ARM core register to scalar:
    - VMOV<c>.<size> <Dd[x]>, <Rt>

    Scalar to ARM core register:
    - VMOV<c>.<dt> <Rt>, <Dn[x]>

    Between ARM core register and signle-precision register:
    - VMOV<c> <Sn>, <Rt>
    - VMOV<c> <Rt>, <Sn>

    Opcode representation:
    ----------------------
    tags[1]: <c>
    args[0]: index of data type in armdictionary
    args[1]: index of destination operand in armdictionary
    args[2]: index of source operand in armdictionary

    xdata format:
    -------------
    vars[0]: destination operand
    xprs[0]: source operand
    xprs[1]: source operand rewritten
    rdefs[0]: reaching definitions for source operand
    uses[0]: uses of destination operand
    useshigh[0]: uses of destination operand in high-level expressions
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

    def _unpack_imm32(self, x: XXpr) -> float:
        # from StackOverflow:
        # https://stackoverflow.com/questions/33483846/how-to-convert-32-bit-binary-to-float

        ci = cast(XprConstant, x).intvalue
        return struct.unpack('f', struct.pack('I', ci))[0]

    def _unpack_imm64(self, x: XXpr) -> float:
        # from StackOverflow:
        # https://stackoverflow.com/questions/8751653/how-to-convert-a-binary-string-into-a-float-value
        ci = cast(XprConstant, x).intvalue
        b8 = struct.pack('Q', ci)
        return struct.unpack('d', b8)[0]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMVectorMoveDSXData(xdata)
        rhs = xd.rxsrc
        lhs = xd.vdst
        if rhs.is_int_constant and str(lhs).startswith("S"):
            f = self._unpack_imm32(rhs)
            return str(lhs) + " := #" + str(f)
        elif rhs.is_int_constant and str(lhs).startswith("D"):
            d = self._unpack_imm64(rhs)
            return str(lhs) + " := #" + str(d)
        else:
            return str(lhs) + " := " + str(rhs)

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VMOV"]

        lhs = xdata.vars[0]
        rhs = xdata.xprs[1]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        (ll_lhs, _, _) = self.opargs[1].ast_lvalue(astree)
        (ll_rhs, _, _) = self.opargs[2].ast_rvalue(astree)
        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)

        if rhs.is_int_constant and str(lhs).startswith("S"):
            # 32-bit floating-point constant
            f = self._unpack_imm32(rhs)
            hl_rhss: List[AST.ASTExpr] = [astree.mk_float_constant(f)]

        elif rhs.is_int_constant and str(lhs).startswith("D"):
            # 64-bit floating-point constant
            f = self._unpack_imm64(rhs)
            hl_rhss = [astree.mk_float_constant(f, fkind="fdouble")]

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

            chklogger.logger.info(
                "Register definition: %s at address %s: %s with %s",
                str(ll_lhs),
                iaddr,
                str(hl_lhs),
                str(hl_rhs))

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
                "VectorMoveDS (VMOV): multiple lval/expressions in ast")
