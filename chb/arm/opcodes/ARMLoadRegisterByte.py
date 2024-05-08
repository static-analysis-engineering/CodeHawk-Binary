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

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.arm.ARMDictionary
    from chb.invariants.XXpr import XprCompound


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
    rdefs[3..]: reaching definitions for memory value
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

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[4] == 1 else ""
        return cc + wide

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

        lhs = xdata.vars[0]
        rhs = xdata.xprs[3]
        memaddr = xdata.xprs[4]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        annotations: List[str] = [iaddr, "LDRB", "addr:" + str(memaddr)]

        (ll_rhs, _, _) = self.opargs[3].ast_rvalue(astree)
        (ll_op1, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_op2, _, _) = self.opargs[2].ast_rvalue(astree)
        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)

        if ll_rhs.is_ast_lval_expr:
            lvalexpr = cast(AST.ASTLvalExpr, ll_rhs)
            if lvalexpr.lval.lhost.is_memref:
                memexp = cast(AST.ASTMemRef, lvalexpr.lval.lhost).memexp
                astree.add_expr_reachingdefs(memexp, [rdefs[0], rdefs[1]])

        hl_rhss = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)
        byteselected = False
        if len(hl_rhss) == 0:
            raise UF.CHBError("LDRB: No rhs value")

        elif len(hl_rhss) == 4:
            hl_rhs = hl_rhss[0]
            byteselected = True

        elif len(hl_rhss) == 1:
            hl_rhs = hl_rhss[0]

        else:
            raise UF.CHBError(
                "LDRB: Multiple rhs values: "
                + ", ".join(str(x) for x in hl_rhss))

        hl_rhs = hl_rhss[0]

        if rhs.is_tmp_variable or rhs.has_unknown_memory_base():
            addrlval = XU.xmemory_dereference_lval(memaddr, xdata, iaddr, astree)
            hl_rhs = astree.mk_lval_expression(addrlval)

        elif (
                rhs.is_compound and cast("XprCompound", rhs).is_lsb
                and cast("XprCompound", rhs).lsb_operand().has_unknown_memory_base()):
            addrlval = XU.xmemory_dereference_lval(memaddr, xdata, iaddr, astree)
            hl_rhs = astree.mk_lval_expression(addrlval)

        elif str(hl_rhs).startswith("localvar"):
            deflocs = xdata.reachingdeflocs_for_s(str(rhs))
            if len(deflocs) == 1:
                definition = astree.localvardefinition(
                    str(deflocs[0]), str(hl_rhs))
                if definition is not None:
                    hl_rhs = definition

        hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        if len(hl_lhss) == 0:
            raise UF.CHBError("LDRB: no lval found")
        if len(hl_lhss) > 1:
            raise UF.CHBError(
                "LDRB: multiple lvals: "
                + ", ".join(str(v) for v in hl_lhss))

        hl_lhs = hl_lhss[0]

        return self.ast_variable_intro(
            astree,
            astree.astree.char_type,
            hl_lhs,
            hl_rhs,
            ll_lhs,
            ll_rhs,
            rdefs[3:],
            rdefs[:2],
            defuses[0],
            defuseshigh[0],
            True,
            iaddr,
            annotations,
            bytestring)
