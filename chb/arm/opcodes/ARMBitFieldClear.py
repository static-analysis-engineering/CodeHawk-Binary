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

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.arm.ARMPseudoCode as APC

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMBitFieldClearXData(ARMOpcodeXData):
    """Data format:
    - variables:
    0: vrd

    - expressions:
    0: xrd
    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vrd(self) -> "XVariable":
        return self.var(0, "vrd")

    @property
    def xrd(self) -> "XXpr":
        return self.xpr(0, "xrd")


@armregistry.register_tag("BFC", ARMOpcode)
class ARMBitFieldClear(ARMOpcode):
    """Clears any number of adjacent bits at any position in a register.

    BFC <Rd>, #<lsb>, #<width>

    tags[1]: <c>
    args[0]: index of Rd in armdictionary
    args[1]: lsb position
    args[2]: width
    args[3]: msb position

    xdata format
    ------------
    rdefs[0]: rhs
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "BitFieldClear")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    @property
    def operandstring(self) -> str:
        return (
            str(self.armd.arm_operand(self.args[0]))
            + ", "
            + str(self.args[1])
            + ", "
            + str(self.args[2]))

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[0])]

    @property
    def lsb(self) -> int:
        return self.args[1]

    @property
    def width(self) -> int:
        return self.args[2]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMBitFieldClearXData(xdata)
        lhs = str(xd.vrd)
        rhs = str(xd.xrd)
        assignment = (
            lhs
            + " := bit-field-clear("
            + rhs
            + ", "
            + str(self.lsb)
            + ", " + str(self.width)
            + ")")
        return xd.add_instruction_condition(assignment)
    '''
        if xdata.has_unknown_instruction_condition():
            return "if ? then " + assignment
        elif xdata.has_instruction_condition():
            c = str(xdata.xprs[1])
            return "if " + c + " then " + assignment
        else:
            return assignment
    '''

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "BFC"]

        lhs = xdata.vars[0]
        rhs = xdata.xprs[0]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        (ll_lhs, _, _) = self.operands[0].ast_lvalue(astree)
        (ll_op1, _, _) = self.operands[0].ast_rvalue(astree)
        maskvalue = APC.bitfieldmask(32, self.lsb, self.width)
        maskconst = astree.mk_integer_constant(maskvalue)
        ll_rhs = astree.mk_binary_op("band", ll_op1, maskconst)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        rdefs = xdata.reachingdefs
        astree.add_expr_reachingdefs(ll_op1, [rdefs[0]])

        # high-level assignment

        xd = ARMBitFieldClearXData(xdata)

        if not xd.is_ok:
            chklogger.logger.error(
                "BFC: Encountered error value for rhs at address %s", iaddr)
            return ([], [ll_assign])

        lhs = xd.vrd
        rhsop = xd.xrd

        '''
        lhsasts = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        if len(lhsasts) == 0:
            raise UF.CHBError("BitFieldClear (BFC): no lval found")

        if len(lhsasts) > 1:
            raise UF.CHBError(
                "BitFieldClear (BFC): multiple lvals found: "
                + ", ".join(str(v) for v in lhsasts))

        hl_lhs = lhsasts[0]

        rhsasts = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)
        if len(rhsasts) == 0:
            raise UF.CHBError("BitFieldClear (BFC): no rhs value found")

        if len(rhsasts) > 1:
            raise UF.CHBError(
                "BitFieldClear (BFC): multiple rhs values found: "
                + ", ".join(str(v) for v in rhsasts))

        hl_rhs1 = rhsasts[0]
        '''

        hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)
        hl_rhsop = XU.xxpr_to_ast_def_expr(rhsop, xdata, iaddr, astree)
        hl_rhs = astree.mk_binary_op("band", hl_rhsop, maskconst)

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
        astree.add_expr_mapping(hl_rhsop, ll_op1)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_op1, [rdefs[0]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        return ([hl_assign], [ll_assign])
