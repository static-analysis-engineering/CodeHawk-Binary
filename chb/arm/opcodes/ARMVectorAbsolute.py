# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2026  Aarno Labs LLC
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

from typing import List, Optional, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

from chb.ast.ARMIntrinsics import ARMIntrinsics

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMVfpDatatype import ARMVfpDatatype
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XprCompound, XprConstant, XXpr


class ARMVectorAbsoluteXData(ARMOpcodeXData):
    """
    Data format:
    - variables:
    0: vdst

    - expressions
    0: xsrc
    1: rxsrc
    """

    def __init__(self, xdata: InstrXData, is_float: bool, size: int) -> None:
        ARMOpcodeXData.__init__(self, xdata)
        self._is_float = is_float
        self._size = size

    @property
    def is_float(self) -> bool:
        return self._is_float

    @property
    def size(self) -> int:
        return self._size

    @property
    def vdst(self) -> "XVariable":
        return self.var(0, "vdst")

    @property
    def xsrc(self) -> "XXpr":
        return self.xpr(0, "xsrc")

    @property
    def rxsrc(self) -> "XXpr":
        return self.xpr(1, "rxsrc")

    @property
    def rxsrc_float(self) -> Optional[float]:
        if self.is_float:
            return ARMOpcodeXData.get_float_conversion(self.rxsrc, self.size)
        else:
            return None

    @property
    def annotation(self) -> str:
        lhs = str(self.vdst)
        f_rhs = self.rxsrc_float
        rhs = str(f_rhs) if f_rhs is not None else str(self.rxsrc)
        assign = f"{lhs} := fabs({rhs}) builtin"
        return self.add_instruction_condition(assign)


@armregistry.register_tag("VABS", ARMOpcode)
class ARMVectorAbsolute(ARMOpcode):
    """Takes the absolute value of each element in a vector.

    tags[1]: <c>
    args[0]: index of datatype in armdictionary
    args[1]: index of destination in armdictionary
    args[2]: index of source in armdictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "VectorAbsolute")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        vfpdt = str(self.armd.arm_vfp_datatype(self.args[0]))
        return cc + vfpdt

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2]]

    @property
    def vfp_datatype(self) -> "ARMVfpDatatype":
        return self.armd.arm_vfp_datatype(self.args[0])

    @property
    def is_float(self) -> bool:
        return self.vfp_datatype.is_float

    @property
    def size(self) -> int:
        return self.vfp_datatype.size

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMVectorAbsoluteXData(xdata, self.is_float, self.size)
        return xd.annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VABS"]

        fabsfvinfo = ARMIntrinsics().fabsf
        fabsftgt = astree.mk_vinfo_lval_expression(fabsfvinfo)

        # low-level assignment

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs, _, _) = self.opargs[1].ast_rvalue(astree)

        ll_call = astree.mk_call(
            ll_lhs,
            fabsftgt,
            [ll_rhs],
            iaddr=iaddr,
            bytestring=bytestring)

        # high-level assignment

        xd = ARMVectorAbsoluteXData(xdata, self.is_float, self.size)

        lhs = xd.vdst
        rhs = xd.rxsrc
        f_rhs = xd.rxsrc_float
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)

        if f_rhs is not None:
            hl_rhs: AST.ASTExpr = astree.mk_float_constant(f_rhs)
        else:
            hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)

        if astree.has_variable_intro(iaddr):
            vname = astree.get_variable_intro(iaddr)
            vdescr = "intro"
        else:
            vname = "fabsf_intrinsic_rtn_" + iaddr
            vdescr = "return value from intrinsic function"

        vinfo = astree.mk_vinfo(
            vname,
            vtype=astree.astree.float_type,
            vdescr=vdescr)
        vinfolval = astree.mk_vinfo_lval(vinfo)
        vinfolvalexpr = astree.mk_lval_expr(vinfolval)

        hl_call = astree.mk_call(
            vinfolval,
            fabsftgt,
            [hl_rhs],
            iaddr=iaddr,
            bytestring=bytestring)

        hl_assign = astree.mk_assign(
            hl_lhs,
            vinfolvalexpr,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_reg_definition(iaddr, hl_lhs, vinfolvalexpr)
        astree.add_instr_mapping(hl_call, ll_call)
        astree.add_instr_address(hl_call, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[0]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        return ([hl_call, hl_assign], [ll_call])
