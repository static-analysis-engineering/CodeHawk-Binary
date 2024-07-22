# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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

from typing import cast, List, Sequence, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData
from chb.app.MemoryAccess import MemoryAccess, RegisterSpill

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
    from chb.arm.ARMOperandKind import ARMRegListOp
    from chb.arm.ARMRegister import ARMRegister


@armregistry.register_tag("PUSH", ARMOpcode)
class ARMPush(ARMOpcode):
    """Stores multiple registers to the stack, and updates the stackpointer.

    PUSH<c> <registers>

    tags[1]: <c>
    args[0]: index of stackpointer in armdictionary
    args[1]: index of register list
    args[2]: is-wide (thumb)

    xdata format: a:vv(n)xxxx(n)rr(n)dd(n)hh(n)  (SP + registers pushed)
    --------------------------------------------------------------------
    vars[0]: SP
    vars[1..n]: v(m) for m: memory location variable
    xprs[0]: SP
    xprs[1]: SP updated
    xprs[2]: SP updated, simplified
    xprs[3..n+2]: x(r) for r: register pushed
    xprs[n+3..2n+3]: xaddr for register pushed
    rdefs[0]: SP
    rdefs[1..n]: rdef(r) for r: register pushed
    uses[0]: SP
    uses[1..n]: uses(m): for m: memory location variable used
    useshigh[0]: SP
    useshigh[1..n]: useshigh(m): for m: memory location variable used at high level
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "Push")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[2] == 1 else ""
        return cc + wide

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1]]

    @property
    def register_count(self) -> int:
        return cast("ARMRegListOp", self.opargs[1].opkind).count

    def memory_accesses(self, xdata: InstrXData) -> Sequence[MemoryAccess]:
        spills = self.register_spills(xdata)
        regcount = self.register_count
        if len(spills) > 0:
            result: List[RegisterSpill] = []
            for (i, spill) in enumerate(spills):
                result.append(RegisterSpill(xdata.xprs[regcount+3+i], spill))
            return result
        else:
            return [MemoryAccess(xdata.xprs[2], "W", size=4)]

    def register_spills(self, xdata: InstrXData) -> List[str]:
        swaddr = xdata.xprs[2]
        result: List[str] = []
        regcount = self.register_count
        # rhs = xdata.xprs[3]
        for rhs in xdata.xprs[3:3+regcount]:
            if rhs.is_initial_register_value:
                r = cast("ARMRegister", rhs.initial_register_value_register())
                if r.is_arm_callee_saved_register:
                    result.append(str(r))
        return result

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:v...x...

        vars[0..n]: stack locations
        xprs[0..n]: register values
        """

        vars = xdata.vars
        xprs = xdata.xprs
        assigns = '; '.join(
            str(v) + " := " + str(x) for (v, x) in zip(vars, xprs[2:]))
        return assigns

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        splhs = xdata.vars[0]
        memlhss = xdata.vars[1:]
        sprrhs = xdata.xprs[0]
        spresult = xdata.xprs[1]
        sprresult = xdata.xprs[2]
        regrhss = xdata.xprs[3:]
        sprdef = xdata.reachingdefs[0]
        regrdefs = xdata.reachingdefs[1:]
        spuses = xdata.defuses[0]
        memuses = xdata.defuses[1:]
        spuseshigh = xdata.defuseshigh[0]
        memuseshigh = xdata.defuseshigh[1:]

        annotations: List[str] = [iaddr, "PUSH"]

        # low-level assignments

        (splval, _, _) = self.opargs[0].ast_lvalue(astree)
        (sprval, _, _) = self.opargs[0].ast_rvalue(astree)

        ll_instrs: List[AST.ASTInstruction] = []
        hl_instrs: List[AST.ASTInstruction] = []
        regsop = self.opargs[1]
        registers = regsop.registers
        sp_decr = 4 * len(registers)
        sp_offset = sp_decr
        for (i, r) in enumerate(registers):
            sp_offset_c = astree.mk_integer_constant(sp_offset)
            addr = astree.mk_binary_op("minus", sprval, sp_offset_c)
            ll_lhs = astree.mk_memref_lval(addr)
            ll_rhs = astree.mk_register_variable_expr(r)
            ll_assign = astree.mk_assign(
                ll_lhs,
                ll_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            ll_instrs.append(ll_assign)

            # high-level assignments

            lhs = memlhss[i]
            rhs = regrhss[i]
            hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)
            hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)

            hl_assign = astree.mk_assign(
                hl_lhs,
                hl_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            hl_instrs.append(hl_assign)

            astree.add_instr_mapping(hl_assign, ll_assign)
            astree.add_instr_address(hl_assign, [iaddr])
            astree.add_expr_mapping(hl_rhs, ll_rhs)
            astree.add_lval_mapping(hl_lhs, ll_lhs)
            astree.add_expr_reachingdefs(ll_rhs, [regrdefs[i]])
            astree.add_lval_defuses(hl_lhs, memuses[i])
            astree.add_lval_defuses_high(hl_lhs, memuseshigh[i])

            sp_offset -= 4

        # low-level SP assignment

        ll_sp_lhs = splval
        sp_decr_c = astree.mk_integer_constant(sp_decr)
        ll_sp_rhs = astree.mk_binary_op("minus", sprval, sp_decr_c)
        ll_sp_assign = astree.mk_assign(
            ll_sp_lhs,
            ll_sp_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)
        ll_instrs.append(ll_sp_assign)

        # high-level SP assignment

        hl_sp_lhs = XU.xvariable_to_ast_lval(splhs, xdata, iaddr, astree)
        hl_sp_rhs = XU.xxpr_to_ast_def_expr(sprresult, xdata, iaddr, astree)
        hl_sp_assign = astree.mk_assign(
            hl_sp_lhs,
            hl_sp_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)
        hl_instrs.append(hl_sp_assign)

        astree.add_instr_mapping(hl_sp_assign, ll_sp_assign)
        astree.add_instr_address(hl_sp_assign, [iaddr])
        astree.add_expr_mapping(hl_sp_rhs, ll_sp_rhs)
        astree.add_lval_mapping(hl_sp_lhs, ll_sp_lhs)
        astree.add_expr_reachingdefs(ll_sp_rhs, [sprdef])
        astree.add_lval_defuses(hl_sp_lhs, spuses)
        astree.add_lval_defuses_high(hl_sp_lhs, spuseshigh)

        return (hl_instrs, ll_instrs)
