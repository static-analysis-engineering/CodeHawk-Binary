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

from typing import cast, List, Sequence, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData
from chb.app.MemoryAccess import MemoryAccess, RegisterSpill

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger
from chb.util.IndexedTable import IndexedTableValue


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMOperandKind import ARMRegListOp
    from chb.arm.ARMRegister import ARMRegister
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMPushXData(ARMOpcodeXData):

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def regcount(self) -> int:
        return len(self._xdata.vars_r) - 1

    @property
    def splhs(self) -> "XVariable":
        return self.var(0, "splhs")

    @property
    def lhsvars(self) -> List["XVariable"]:
        return [self.var(i, "lhsvar") for i in range(1, self.regcount + 1)]

    @property
    def sprhs(self) -> "XXpr":
        return self.xpr(0, "sprhs")

    @property
    def spresult(self) -> "XXpr":
        return self.xpr(1, "spresult")

    @property
    def rspresult(self) -> "XXpr":
        return self.xpr(2, "rspresult")

    @property
    def rrhsexprs(self) -> List["XXpr"]:
        return [self.xpr(i, "rhsvar") for i in range(3, self.regcount + 3)]

    @property
    def xaddrs(self) -> List["XXpr"]:
        return [self.xpr(i, "xaddr")
                for i in range(self.regcount + 3, (2 * self.regcount) + 3)]

    @property
    def annotation(self) -> str:
        pairs = zip(self.lhsvars, self.rrhsexprs)
        spassign = str(self.splhs) + " := " + str(self.rspresult)
        assigns = "; ".join(str(v) + " := " + str(x) for (v, x) in pairs)
        assigns = spassign + "; " + assigns
        return self.add_instruction_condition(assigns)


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

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
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
        xd = ARMPushXData(xdata)
        spills = self.register_spills(xdata)
        regcount = self.register_count
        if len(spills) > 0:
            result: List[RegisterSpill] = []
            for (i, spill) in enumerate(spills):
                result.append(RegisterSpill(xd.xaddrs[i], spill))
            return result
        else:
            return [MemoryAccess(xdata.xprs[2], "W", size=4)]

    def register_spills(self, xdata: InstrXData) -> List[str]:
        xd = ARMPushXData(xdata)
        result: List[str] = []
        regcount = self.register_count
        # rhs = xdata.xprs[3]
        for rhs in xd.rrhsexprs:
            if rhs.is_initial_register_value:
                r = cast("ARMRegister", rhs.initial_register_value_register())
                if r.is_arm_callee_saved_register:
                    result.append(str(r))
        return result

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMPushXData(xdata)
        if xd.is_ok:
            return xd.annotation
        else:
            return "Error value"

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        xd = ARMPushXData(xdata)
        if not xd.is_ok:
            chklogger.logger.error(
                "Encountered error value at address %s", iaddr)

        splhs = xd.splhs
        memlhss = xd.lhsvars
        sprrhs = xd.spresult
        sprresult = xd.rspresult
        regrhss = xd.rrhsexprs

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

            regrdef = regrdefs[i]
            lhs = memlhss[i]
            rhs = regrhss[i]

            # if a reaching definition includes a definition from a clobbered
            # variable, saving the value is meaningless in the program
            if regrdef is not None and regrdef.has_clobbered_defs():
               chklogger.logger.info(
                   "Skip spill of %s at %s due to clobbered definition",
                   str(rhs), iaddr)

            elif astree.is_in_wrapper(iaddr):
                chklogger.logger.info(
                    "Skip spill of %s (%s) at %s within trampoline wrapper",
                    str(ll_rhs), str(rhs), iaddr)

            else:

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
                astree.add_expr_reachingdefs(ll_rhs, [regrdef])
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
