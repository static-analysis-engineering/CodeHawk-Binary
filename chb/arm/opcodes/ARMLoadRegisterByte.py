# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.arm.ARMDictionary


@armregistry.register_tag("LDRB", ARMOpcode)
class ARMLoadRegisterByte(ARMOpcode):
    """Loads a byte from memory, zero-extends it to 32 bits, and writes it to a register.

    LDRB<c> <Rt>, [<base>, <offset>]

    tags[0]: <c>
    args[0]: index of destination operand in armdictionary
    args[1]: index of base register in armdictionary
    args[2]: index of index in armdictionary
    args[3]: index of memory location in armdictionary
    args[4]: is-wide (thumb)

    xdata format: a:vxxxxrrrdh
    --------------------------
    vars[0]: lhs
    vars[1]: memory location expressed as a variable
    xprs[0]: value in rn
    xprs[1]: value in rm
    xprs[2]: value in memory location
    xprs[3]: value in memory location (simplified)
    xprs[4]: address of memory location
    rdefs[0]: reaching definitions rn
    rdefs[1]: reaching definitions rm
    rdefs[2]: reaching definitions memory location
    uses[0]: use of lhs
    useshigh[0]: use of lhs at high level

    optional:
    vars[1]: lhs base register (if base update)

    xprs[.]: instruction condition (if has condition)
    xprs[.]: new address for base register
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "LoadRegisterByte")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 3]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1, 2, 3]]

    def is_load_instruction(self, xdata: InstrXData) -> bool:
        return True

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return [xdata.xprs[1]]

    def annotation(self, xdata: InstrXData) -> str:
        """lhs, rhs, with optional instr condition and base update."""

        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[3])

        xctr = 4
        if xdata.has_instruction_condition():
            pcond = "if " + str(xdata.xprs[xctr]) + " then "
            xctr += 1
        elif xdata.has_unknown_instruction_condition():
            pcond = "if ? then "
        else:
            pcond = ""

        vctr = 2
        if xdata.has_base_update():
            blhs = str(xdata.vars[vctr])
            brhs = str(xdata.xprs[xctr])
            pbupd = "; " + blhs + " := " + brhs
        else:
            pbupd = ""

        return pcond + lhs + " := " + rhs + pbupd

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "LDRB"]

        (ll_rhs, ll_preinstrs, ll_postinstrs) = self.opargs[3].ast_rvalue(astree)
        (ll_op1, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_op2, _, _) = self.opargs[2].ast_rvalue(astree)
        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        lhs = xdata.vars[0]
        rhs = xdata.xprs[3]
        memaddr = xdata.xprs[4]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_preinstrs: List[AST.ASTInstruction] = []
        hl_postinstrs: List[AST.ASTInstruction] = []

        rhsexprs = XU.xxpr_to_ast_exprs(rhs, xdata, astree)
        byteselected = False
        if len(rhsexprs) == 0:
            raise UF.CHBError("No rhs for LoadRegisterByte (LDRB)")

        elif len(rhsexprs) == 4:
            hl_rhs = rhsexprs[0]
            byteselected = True

        elif len(rhsexprs) == 1:
            hl_rhs = rhsexprs[0]

        else:
            raise UF.CHBError(
                "Multiple rhs values for LoadRegisterByte (LDRB): "
                + ", ".join(str(x) for x in rhsexprs))

        hl_rhs = rhsexprs[0]
        if str(hl_rhs).startswith("__asttmp") or str(hl_rhs).startswith("(__asttmp"):
            addrlval = XU.xmemory_dereference_lval(xdata.xprs[4], xdata, iaddr, astree)
            hl_rhs = astree.mk_lval_expression(addrlval)

        if str(hl_rhs).startswith("localvar"):
            deflocs = xdata.reachingdeflocs_for_s(str(rhs))
            if len(deflocs) == 1:
                definition = astree.localvardefinition(str(deflocs[0]), str(hl_rhs))
                if definition is not None:
                    hl_rhs = definition

        hl_lhs = astree.mk_register_variable_lval(str(lhs))

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
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(hl_rhs, [rdefs[2]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        if ll_rhs.is_ast_lval_expr:
            lvalexpr = cast(AST.ASTLvalExpr, ll_rhs)
            if lvalexpr.lval.lhost.is_memref:
                memexp = cast(AST.ASTMemRef, lvalexpr.lval.lhost).memexp
                astree.add_expr_reachingdefs(memexp, [rdefs[0], rdefs[1]])

        return ([hl_assign], [ll_assign])
