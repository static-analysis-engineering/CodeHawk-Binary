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


@armregistry.register_tag("POP", ARMOpcode)
class ARMPop(ARMOpcode):
    """Loads multiple registers from the stack, and updates the stackpointer.

    POP<c> <registers>

    tags[1]: <c>
    args[0]: index of stackpointer operand in armdictionary
    args[1]: index of register list in armdictionary
    args[2]: is-wide (thumb)

    xdata format: a:vv(n)xxxx(n)rr(n)dd(n)hh(n)   (SP + registers popped)
    ---------------------------------------------------------------------
    vars[0]: SP
    vars[1..n]: v(r) for r: register popped
    xprs[0]: SP
    xprs[1]: SP updated
    xprs[2]: SP updated, simplified
    xprs[3..n+2]: x(m) for m: memory location value retrieved
    rdefs[0]: SP
    rdefs[1..n]: rdef(m) for m: memory location variable
    uses[0}: SP
    uses[1..n]: uses(r) for r: register popped
    useshigh[0]: SP
    useshigh[1..n]: useshigh(r): for r: register popped used at high level
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "Pop")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1]]

    @property
    def operandstring(self) -> str:
        return str(self.operands[1])

    def is_return_instruction(self, xdata: InstrXData) -> bool:
        vars = xdata.vars
        xprs = xdata.xprs
        xctr = len(vars)
        pairs = zip(vars, xprs[:xctr])
        for (v, x) in pairs:
            if str(v) == "PC" and str(x) == "LR_in":
                return True
        else:
            return False

    def annotation(self, xdata: InstrXData) -> str:
        vars = xdata.vars
        xprs = xdata.xprs

        xctr = len(vars)
        pairs = zip(vars, xprs[2:])
        assigns = "; ".join(str(v) + " := " + str(x) for (v, x) in pairs)

        if xdata.has_instruction_condition():
            pcond = "if " + str(xprs[xctr]) + " then "
            xctr += 1
        elif xdata.has_unknown_instruction_condition():
            pcond = "if ? then "
        else:
            pcond = ""

        return pcond + assigns

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        splhs = xdata.vars[0]
        reglhss = xdata.vars[1:]
        sprrhs = xdata.xprs[0]
        spresult = xdata.xprs[1]
        sprresult = xdata.xprs[2]
        memrhss = xdata.xprs[3:]
        sprdef = xdata.reachingdefs[0]
        memrdefs = xdata.reachingdefs[1:]
        spuses = xdata.defuses[0]
        reguses = xdata.defuses[1:]
        spuseshigh = xdata.defuseshigh[0]
        reguseshigh = xdata.defuseshigh[1:]

        annotations: List[str] = [iaddr, "POP"]

        (splval, _, _) = self.opargs[0].ast_lvalue(astree)
        (sprval, _, _) = self.opargs[0].ast_rvalue(astree)

        ll_instrs: List[AST.ASTInstruction] = []
        hl_instrs: List[AST.ASTInstruction] = []
        regsop = self.opargs[1]
        registers = regsop.registers
        sp_incr = 4 * len(registers)
        sp_offset = 0
        for (i, r) in enumerate(registers):
            sp_offset_c = astree.mk_integer_constant(sp_offset)
            addr = astree.mk_binary_op("plus", sprval, sp_offset_c)
            ll_lhs = astree.mk_variable_lval(r)
            ll_rhs = astree.mk_memref_expr(addr)
            ll_assign = astree.mk_assign(ll_lhs, ll_rhs, iaddr=iaddr)
            ll_instrs.append(ll_assign)

            lhs = reglhss[i]
            rhs = memrhss[i]
            hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
            hl_rhss = XU.xxpr_to_ast_exprs(rhs, xdata, astree)
            if len(hl_lhss) != 1 and len(hl_rhss) != 1:
                raise UF.CHBError(
                    "ARMPop: more than one lhs or ths in assignments")
            hl_lhs = hl_lhss[0]
            hl_rhs = hl_rhss[0]

            if str(hl_rhs).startswith("localvar"):
                deflocs = xdata.reachingdeflocs_for_s(str(rhs))
                if len(deflocs) == 1:
                    definition = astree.localvardefinition(str(deflocs[0]), str(hl_rhs))
                    if definition is not None:
                        hl_rhs = definition

            hl_assign = astree.mk_assign(
                hl_lhs,
                hl_rhs,
                iaddr=iaddr,
                annotations=annotations)
            hl_instrs.append(hl_assign)

            astree.add_reg_definition(iaddr, hl_lhs, hl_rhs)
            astree.add_instr_mapping(hl_assign, ll_assign)
            astree.add_instr_address(hl_assign, [iaddr])
            astree.add_expr_mapping(hl_rhs, ll_rhs)
            astree.add_lval_mapping(hl_lhs, ll_lhs)
            astree.add_expr_reachingdefs(ll_rhs, [memrdefs[i]])
            astree.add_lval_defuses(hl_lhs, reguses[i])
            astree.add_lval_defuses_high(hl_lhs, reguseshigh[i])

            sp_offset += 4

        ll_sp_lhs = splval
        sp_incr_c = astree.mk_integer_constant(sp_incr)
        ll_sp_rhs = astree.mk_binary_op("plus", sprval, sp_incr_c)
        ll_sp_assign = astree.mk_assign(ll_sp_lhs, ll_sp_rhs, iaddr=iaddr)
        ll_instrs.append(ll_sp_assign)

        hl_sp_lhss = XU.xvariable_to_ast_lvals(splhs, xdata, astree)
        hl_sp_rhss = XU.xxpr_to_ast_exprs(sprresult, xdata, astree)
        if len(hl_sp_lhss) != 1 or len(hl_sp_rhss) != 1:
            raise UF.CHBError(
                "ARMPop more than one lhs or rhs in SP assignment")
        hl_sp_lhs = hl_sp_lhss[0]
        hl_sp_rhs = hl_sp_rhss[0]
        hl_sp_assign = astree.mk_assign(hl_sp_lhs, hl_sp_rhs, iaddr=iaddr)
        hl_instrs.append(hl_sp_assign)

        astree.add_instr_mapping(hl_sp_assign, ll_sp_assign)
        astree.add_instr_address(hl_sp_assign, [iaddr])
        astree.add_expr_mapping(hl_sp_rhs, ll_sp_rhs)
        astree.add_lval_mapping(hl_sp_lhs, ll_sp_lhs)
        astree.add_expr_reachingdefs(ll_sp_rhs, [sprdef])
        astree.add_lval_defuses(hl_sp_lhs, spuses)
        astree.add_lval_defuses_high(hl_sp_lhs, spuseshigh)

        return (hl_instrs, ll_instrs)
