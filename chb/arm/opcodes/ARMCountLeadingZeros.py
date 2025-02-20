# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2025 Aarno Labs LLC
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
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMCountLeadingZerosXData(ARMOpcodeXData):
    """CLZ <rd> <rn>"""

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vrd(self) -> "XVariable":
        return self.var(0, "vrd")

    @property
    def xrn(self) -> "XXpr":
        return self.xpr(0, "xrn")

    @property
    def xxrn(self) -> "XXpr":
        return self.xpr(1, "xxrn")



@armregistry.register_tag("CLZ", ARMOpcode)
class ARMCountLeadingZeros(ARMOpcode):
    """Counts the number of zero bits before the first binary one bit in a value.

    CLZ<c> <Rd>, <Rm>

    tags[1]: <c>
    args[0]: index of Rd in armdictionary
    args[1]: index of Rm in armdictionary

    xdata format: a:vxxr..dh
    ------------------------
    vars[0]: lhs
    xprs[0]: rhs
    xprs[1]: rhs (rewritten)
    rdefs[0]: rhs
    uses: lhs
    useshigh: lhs
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 2, "CountLeadingZeros")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMCountLeadingZerosXData(xdata)
        if xd.is_ok:
            lhs = str(xd.vrd)
            rhs = str(xd.xxrn)
            assignment = lhs + " := __clz(" + rhs + ") (intrinsic)"
            return assignment
        else:
            return "Error value"

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        """Return intrinsic function call __clz.

        From: ARM C Language Extensions. Release 2.1
        Date: 24/03/2016
        Section 9.2

        unsigned_int __clz(uint32_t x);
        Returns the number of leading zero bits in x. When x is zero
        it returns 32.
        """

        # Assume 32-bit architecture, that is, unsigned int :: uint32_t
        clzsig = astree.mk_function_with_arguments_type(
            astree.astree.unsigned_int_type,
            [("x", astree.astree.unsigned_int_type)])
        clztgt = astree.mk_named_lval_expression(
            "__clz",
            vtype=clzsig,
            globaladdress=0,
            vdescr="arm intrinsic")

        annotations: List[str] = [iaddr, "CLZ"]

        lhs = xdata.vars[0]
        rhs = xdata.xprs[1]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs, _, _) = self.opargs[1].ast_rvalue(astree)

        ll_call = astree.mk_call(
            ll_lhs,
            clztgt,
            [ll_rhs],
            iaddr=iaddr,
            bytestring=bytestring)

        lhsasts = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        if len(lhsasts) == 0:
            raise UF.CHBError(
                "CountLeadingZeros (CLZ): no lval found")

        if len(lhsasts) > 1:
            raise UF.CHBError(
                "CountLeadingZeros (CLZ): multiple lvals in ast: "
                + ", ".join(str(v) for v in lhsasts))

        hl_lhs = lhsasts[0]

        rhsasts = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)
        if len(rhsasts) == 0:
            raise UF.CHBError(
                "CountLeadingZeros (CLZ): no argument value found")

        if len(rhsasts) > 1:
            raise UF.CHBError(
                "CountLeadingZeros (CLZ): "
                + "multiple argument values in asts: "
                + ", ".join(str(x) for x in rhsasts))

        hl_rhs = rhsasts[0]

        if astree.has_variable_intro(iaddr):
            vname = astree.get_variable_intro(iaddr)
            vdescr = "intro"
        else:
            vname = "clz_intrinsic_rtn_" + iaddr
            vdescr = "return value from intrinsic function"

        vinfo = astree.mk_vinfo(
            vname,
            vtype=astree.astree.unsigned_int_type,
            vdescr=vdescr)
        vinfolval = astree.mk_vinfo_lval(vinfo)
        vinfolvalexpr = astree.mk_lval_expr(vinfolval)

        hl_call = astree.mk_call(
            vinfolval,
            clztgt,
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
