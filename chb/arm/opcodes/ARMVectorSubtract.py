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


class ARMVectorSubtractXData(ARMOpcodeXData):
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

    @property
    def annotation(self) -> str:
        lhs = str(self.vdst)
        rhs1 = str(self.rxsrc1)
        rhs2 = str(self.rxsrc2)
        assign = lhs + " := " + rhs1 + " - " + rhs2
        return self.add_instruction_condition(assign)


@armregistry.register_tag("VSUB", ARMOpcode)
class ARMVectorSubtract(ARMOpcode):
    """Subtracts elements from one vector from elements of another vector.

    VSUB<c>.<dt> <Qd>, <Qn>, <Qm>
    VSUB<c>.<dt> <Dd>, <Dn>, <Dm>

    VSUB<c>.F64 <Dd>, <Dn>, <Dm>
    VSUB<c>.F32 <Sd>, <Sn>, <Sm>

    tags[1]: <c>
    args[0]: index of datatype in armdictionary
    args[1]: index of qd in armdictionary
    args[2]: index of qn in armdictionary
    args[3]: index of qm in armdictionary

    xdata format:
    -------------
    vars[0]: lhs
    xprs[0]: first source value
    xprs[1]: second source value
    xprs[2]: destination register value
    xprs[3]: first source value rewritten
    xprs[4]: second source value rewritten
    xprs[5]: destination register value rewritten
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "VectorSubtract")

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
        xd = ARMVectorSubtractXData(xdata)
        return xd.annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VSUB"]
        xd = ARMVectorSubtractXData(xdata)

        lhs = xd.vdst
        rhs1 = xd.rxsrc1
        rhs2 = xd.rxsrc2
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs1, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_rhs2, _, _) = self.opargs[2].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("minus", ll_rhs1, ll_rhs2)

        lhsasts = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        if len(lhsasts) != 1:
            raise UF.CHBError("ARMSubtract: no or multiple lvals in ast")

        hl_lhs = lhsasts[0]

        rhs1asts = XU.xxpr_to_ast_def_exprs(rhs1, xdata, iaddr, astree)
        rhs2asts = XU.xxpr_to_ast_def_exprs(rhs2, xdata, iaddr, astree)
        if len(rhs1asts) == 1 and len(rhs2asts) == 1:
            rhsast1 = rhs1asts[0]
            rhsast2 = rhs2asts[0]
        else:
            raise UF.CHBError(
                "ARMVectorSubtract: multiple expressions in ast rhs")

        hl_rhs = astree.mk_binary_op("minus", rhsast1, rhsast2)
        return self.ast_variable_intro(
            astree,
            astree.astree.int_type,
            hl_lhs,
            hl_rhs,
            ll_lhs,
            ll_rhs,
            rdefs[2:],
            rdefs[:2],
            defuses[0],
            defuseshigh[0],
            True,
            iaddr,
            annotations,
            bytestring)
