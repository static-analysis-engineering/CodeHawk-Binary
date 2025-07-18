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
from chb.app.MemoryAccess import MemoryAccess, RegisterRestore

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMRegister import ARMRegister
    from chb.invariants.VAssemblyVariable import (
        VAuxiliaryVariable, VRegisterVariable)
    from chb.invariants.VConstantValueVariable import VInitialRegisterValue
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMLoadRegisterDualXData(ARMOpcodeXData):

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vrt(self) -> "XVariable":
        return self.var(0, "vrt")

    @property
    def vrt2(self) -> "XVariable":
        return self.var(1, "vrt2")

    @property
    def vmem(self) -> "XVariable":
        return self.var(2, "vmem")

    @property
    def vmem2(self) -> "XVariable":
        return self.var(3, "vmem2")

    @property
    def xrn(self) -> "XXpr":
        return self.xpr(0, "xrn")

    @property
    def xrm(self) -> "XXpr":
        return self.xpr(1, "xrm")

    @property
    def xmem(self) -> "XXpr":
        return self.xpr(2, "xmem")

    @property
    def xrmem(self) -> "XXpr":
        return self.xpr(3, "xrmem")

    @property
    def xmem2(self) -> "XXpr":
        return self.xpr(4, "xmem2")

    @property
    def xrmem2(self) -> "XXpr":
        return self.xpr(5, "xrmem2")

    @property
    def xaddr1(self) -> "XXpr":
        return self.xpr(6, "xaddr1")

    @property
    def xaddr2(self) -> "XXpr":
        return self.xpr(7, "xaddr2")

    @property
    def annotation(self) -> str:
        assignment = (
            str(self.vrt) + " := " + str(self.xrmem) + "; "
            + str(self.vrt2) + " := " + str(self.xrmem2) )
        wbu = self.writeback_update()
        return self.add_instruction_condition(assignment + wbu)


@armregistry.register_tag("LDRD", ARMOpcode)
class ARMLoadRegisterDual(ARMOpcode):
    """Loads two words from memory and writes them to two register.

    LDRD<c> <Rt>, <Rt2>, [PCm #-0]

    tags[1]: <c>
    args[0]: index of first destination operand in armdictionary
    args[1]: index of second destination operand in armdictionary
    args[2]: index of base register in armdictionary
    args[3]: index of index register / immediate in armdictionary
    args[4]: index of memory location in armdictionary
    args[5]: index of second memory location in armdictionary

    xdata format: a:vvvvxxxxxxxxrrrrddhh
    ------------------------------------
    vars[0]: vrt
    vars[1]: vrt2
    vars[2]: memvar1
    vars[3]: memvar2
    xprs[0]: xrn (base register)
    xprs[1]: xrm (index)
    xprs[2]: memval1
    xprs[3]: memval1 (simplified)
    xprs[4]: memval2
    xprs[5]: memval2 (simplified)
    xprs[6]: memory address 1
    xprs[7]: memory address 2
    rdefs[0]: xrn
    rdefs[1]: xrm
    rdefs[2]: memvar1
    rdefs[3]: memvar2
    defuse[0]: vrt
    defuse[1]: vrt2
    defusehigh[0]: vrt
    defusehigh[1]: vrt2
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 6, "LoadRegisterDual")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1, 4]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[1]) for i in range(0, 6)]

    def memory_accesses(self, xdata: InstrXData) -> Sequence[MemoryAccess]:
        restores = self.register_restores(xdata)
        xd = ARMLoadRegisterDualXData(xdata)
        if len(restores) == 2:
            return [
                RegisterRestore(xd.xaddr1, restores[0]),
                RegisterRestore(xd.xaddr2, restores[1])]
        else:
            return [
                MemoryAccess(xd.xaddr1, "R", size=4),
                MemoryAccess(xd.xaddr2, "R", size=4)]

    def register_restores(self, xdata: InstrXData) -> List[str]:
        result: List[str] = []
        xd = ARMLoadRegisterDualXData(xdata)
        if (self.operands[0].is_register):
            r1 = cast(
                "ARMRegister",
                cast("VRegisterVariable", xd.vrt.denotation).register)
            if r1.is_arm_callee_saved_register:
                # rhs1 = xdata.xprs[3]
                rhs1 = xd.xrmem
                if rhs1.is_initial_register_value:
                    rr1 = rhs1.initial_register_value_register()
                    if str(rr1) == str(r1):
                        result.append(str(rr1))
            r2 = cast(
                "ARMRegister",
                cast("VRegisterVariable", xd.vrt2.denotation).register)
            if r2.is_arm_callee_saved_register:
                # rhs2 = xdata.xprs[5]
                rhs2 = xd.xrmem2
                if rhs2.is_initial_register_value:
                    rr2 = rhs2.initial_register_value_register()
                    if str(rr2) == str(r2):
                        result.append(str(rr2))
        return result

    def is_load_instruction(self, xdata: InstrXData) -> bool:
        return True

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return [xdata.xprs[1], xdata.xprs[3]]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMLoadRegisterDualXData(xdata)
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

        xd = ARMLoadRegisterDualXData(xdata)
        memaddr = xd.xaddr1

        annotations: List[str] = [iaddr, "LDRD", "addr: " + str(memaddr)]

        # low-level assignments

        (ll_rhs1, ll_pre1, ll_post1) = self.opargs[4].ast_rvalue(
            astree, iaddr=iaddr, bytestring=bytestring)
        (ll_lhs1, _, _) = self.opargs[0].ast_lvalue(astree)

        ll_assign1 = astree.mk_assign(
            ll_lhs1,
            ll_rhs1,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        (ll_rhs2, ll_pre2, ll_post2) = self.opargs[5].ast_rvalue(
            astree, iaddr=iaddr, bytestring=bytestring)
        (ll_lhs2, _, _) = self.opargs[1].ast_lvalue(astree)

        ll_assign2 = astree.mk_assign(
            ll_lhs2,
            ll_rhs2,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignments

        if not xd.is_ok:
            chklogger.logger.error(
                "Encountered error value at address %s", iaddr)
            return ([], [])

        lhs1 = xd.vrt
        lhs2 = xd.vrt2
        rhs1 = xd.xrmem
        rhs2 = xd.xrmem2

        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_rhs1 = XU.xxpr_to_ast_def_expr(rhs1, xdata, iaddr, astree)
        hl_lhs1 = XU.xvariable_to_ast_lval(lhs1, xdata, iaddr, astree)

        hl_assign1 = astree.mk_assign(
            hl_lhs1,
            hl_rhs1,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        hl_rhs2 = XU.xxpr_to_ast_def_expr(rhs2, xdata, iaddr, astree)
        hl_lhs2 = XU.xvariable_to_ast_lval(lhs2, xdata, iaddr, astree)

        hl_assign2 = astree.mk_assign(
            hl_lhs2,
            hl_rhs2,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # TODO: add writeback

        astree.add_instr_mapping(hl_assign1, ll_assign1)
        astree.add_instr_mapping(hl_assign2, ll_assign2)
        astree.add_instr_address(hl_assign1, [iaddr])
        astree.add_instr_address(hl_assign2, [iaddr])
        astree.add_expr_mapping(hl_rhs1, ll_rhs1)
        astree.add_expr_mapping(hl_rhs2, ll_rhs2)
        astree.add_lval_mapping(hl_lhs1, ll_lhs1)
        astree.add_lval_mapping(hl_lhs2, ll_lhs2)
        astree.add_expr_reachingdefs(ll_rhs1, rdefs)
        astree.add_expr_reachingdefs(ll_rhs2, rdefs)
        astree.add_lval_defuses(hl_lhs1, defuses[0])
        astree.add_lval_defuses(hl_lhs2, defuses[1])

        ll_assigns: List[AST.ASTInstruction] = (
            ll_pre1 + ll_pre2 + [ll_assign1, ll_assign2] + ll_post1 + ll_post2)
        hl_assigns: List[AST.ASTInstruction] = [hl_assign1, hl_assign2]

        return (hl_assigns, ll_assigns)
