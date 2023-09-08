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

from typing import cast, List, Tuple, TYPE_CHECKING

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
    import chb.arm.ARMDictionary
    from chb.invariants.XXpr import XprCompound, XprConstant


@armregistry.register_tag("SUBW", ARMOpcode)
@armregistry.register_tag("SUB", ARMOpcode)
class ARMSubtract(ARMOpcode):
    """Subtracts a value from a register and saves the result in a register.

    SUB{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}

    tags[1]: <c>
    args[0]: {S}
    args[1]: index of op1 in armdictionary
    args[2]: index of op2 in armdictionary
    args[3]: index of op3 in armdictionary
    args[4]: is-wide (thumb)
    args[5]: wide

    xdata format: a:vxxxxrrdh
    -------------------------
    vars[0]: lhs (Rd)
    xprs[0]: rhs1 (Rn)
    xprs[1]: rhs2 (Rm)
    xprs[2]: rhs1 - rhs2
    xprs[3]: rhs1 - rhs2 (simplified)
    rdefs[0]: rhs1
    rdefs[1]: rhs2
    rdefs[2..]: reaching definitions for simplified result
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 6, "Subtract")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wb = "S" if self.is_writeback else ""
        wide = ".W" if self.is_thumb_wide else ""
        return wb + cc + wide

    @property
    def is_thumb_wide(self) -> bool:
        return self.args[4] == 1

    @property
    def is_wide(self) -> bool:
        return self.args[5] == 1

    @property
    def is_writeback(self) -> bool:
        return self.args[0] == 1

    def annotation(self, xdata: InstrXData) -> str:
        lhs = str(xdata.vars[0])
        result = xdata.xprs[2]
        rresult = xdata.xprs[3]
        xresult = simplify_result(xdata.args[3], xdata.args[4], result, rresult)
        return lhs + " := " + xresult

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "SUB"]

        lhs = xdata.vars[0]
        rhs1 = xdata.xprs[0]
        rhs2 = xdata.xprs[1]
        rhs3 = xdata.xprs[3]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_op1, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_op2, _, _) = self.opargs[2].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("minus", ll_op1, ll_op2)

        astree.add_expr_reachingdefs(ll_op1, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_op2, [rdefs[1]])

        lhsasts = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        if len(lhsasts) != 1:
            raise UF.CHBError("ARMSubtract: no or multiple lvals in ast")

        hl_lhs = lhsasts[0]

        # resulting expression is a stack address
        if str(rhs1) == "SP" and rhs3.is_stack_address:
            annotations.append("stack address")
            rhs3 = cast("XprCompound", rhs3)
            stackoffset = rhs3.stack_address_offset()
            rhslval = astree.mk_stack_variable_lval(stackoffset)
            rhsast: AST.ASTExpr = astree.mk_address_of(rhslval)

        elif str(rhs1) == "PC" or str(rhs2) == "PC":
            annotations.append("PC-relative")
            if rhs3.is_int_constant:
                rhsval = cast("XprConstant", rhs3).intvalue
                rhsast = astree.mk_integer_constant(rhsval)
            else:
                rhsasts = XU.xxpr_to_ast_exprs(rhs3, xdata, iaddr, astree)
                if len(rhsasts) == 1:
                    rhsast = rhsasts[0]
                else:
                    raise UF.CHBError(
                        "ARMSubtract: multiple expressions in ast rhs")

        else:
            rhsasts = XU.xxpr_to_ast_def_exprs(rhs3, xdata, iaddr, astree)
            if len(rhsasts) == 1:
                rhsast = rhsasts[0]
            else:
                raise UF.CHBError(
                    "ARMSubtract: multiple expressions in ast rhs")

        hl_rhs = rhsast
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
