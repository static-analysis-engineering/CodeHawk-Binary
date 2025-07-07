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

from typing import cast, List, Tuple, TYPE_CHECKING

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
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XprCompound, XprConstant, XXpr


class ARMByteReversePackedHalfwordXData(ARMOpcodeXData):
    """REV16 <rd> <rm>"""

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vrd(self) -> "XVariable":
        return self.var(0, "vrd")

    @property
    def xrm(self) -> "XXpr":
        return self.xpr(0, "xrm")

    @property
    def xxrm(self) -> "XXpr":
        return self.xpr(1, "xxrm")

    @property
    def annotation(self) -> str:
        if self.is_ok:
            lhs = str(self.vrd)
            rhs = str(self.xxrm)
            assign = lhs + " := __rev16(" + str(rhs) + ") intrinsic"
            return self.add_instruction_condition(assign)
        else:
            return "REV16: error"


@armregistry.register_tag("REV16", ARMOpcode)
class ARMByteReversePackedHalfword(ARMOpcode):
    """Reverses the byte order in each 16-bit halfword of a 32-bit register.

    REV16<c> <Rd>, <Rm>

    tags[1]: <c>
    args[0]: index of Rd in armdictionary
    args[1]: index of Rm in armdictionary
    args[2]: Thumb.wide

    xdata format: a:vxxr..dh
    ------------------------
    vars[0]: lhs (Rd)
    xprs[0]: rhs (Rm)
    xprs[0]: rhs (Rm) (rewritten)
    rdefs[0]: rhs
    rdefs[1..]: rdefs for Rm rewritten
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "ByteReversePackedHalfword")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[:-1]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[2] == 1 else ""
        return cc + wide

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[:-1]]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMByteReversePackedHalfwordXData(xdata)
        return xd.annotation

    # --------------------------------------------------------------------------
    # Operation
    #   bits(32) result;
    #   result<31:24> = R[m]<23:16>;
    #   result<23:16> = R[m]<31:24>;
    #   result<15:8> = R[m]<7:0>
    #   result<7:0> = R[m]<15:8>
    #   R[d] = result;
    # --------------------------------------------------------------------------

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        """Return the intrinsic funciton call __rev16.

        From: ARM C Language Extensions. Release 2.1
        Date: 24/03/2016
        Section 9.2

        uint32_t __rev16(uint32_t x);
        Reverses the byte order within each halfword of a word.
        """

        rev16vinfo = ARMIntrinsics().rev16
        rev16tgt = astree.mk_vinfo_lval_expression(rev16vinfo)

        annotations: List[str] = [iaddr, "REV16"]

        # low-level assignment

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs, _, _) = self.opargs[1].ast_rvalue(astree)

        ll_call = astree.mk_call(
            ll_lhs,
            rev16tgt,
            [ll_rhs],
            iaddr=iaddr,
            bytestring=bytestring)

        # high-level assignment

        xd = ARMByteReversePackedHalfwordXData(xdata)
        if not xd.is_ok:
            chklogger.logger.error(
                "Encountered error value at address %s", iaddr)
            return ([], [])

        lhs = xd.vrd
        rhs = xd.xxrm

        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)
        hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)

        if astree.has_variable_intro(iaddr):
            vname = astree.get_variable_intro(iaddr)
            vdescr = "intro"
        else:
            vname = "rev16_intrinsic_rtn_" + iaddr
            vdescr = "return value from intrinsic function"

        vinfo = astree.mk_vinfo(
            vname,
            vtype=astree.astree.unsigned_short_type,
            vdescr=vdescr)
        vinfolval = astree.mk_vinfo_lval(vinfo)
        vinfolvalexpr = astree.mk_lval_expr(vinfolval)

        hl_call = astree.mk_call(
            vinfolval,
            rev16tgt,
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
