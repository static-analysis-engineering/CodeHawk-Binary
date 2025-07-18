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

from typing import cast, List, Optional, Sequence, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData
from chb.app.MemoryAccess import MemoryAccess, RegisterSpill

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand
from chb.arm.ARMRegister import ARMRegister

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.VarInvariantFact import ReachingDefFact
    from chb.invariants.VAssemblyVariable import VMemoryVariable
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMStoreRegisterDualXData(ARMOpcodeXData):

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vmem1(self) -> "XVariable":
        return self.var(0, "vmem1")

    @property
    def is_vmem_known(self) -> bool:
        return self.xdata.vars_r[0] is not None

    @property
    def vmem2(self) -> "XVariable":
        return self.var(1, "vmem2")

    @property
    def xrn(self) -> "XXpr":
        return self.xpr(0, "xrn")

    @property
    def xrm(self) -> "XXpr":
        return self.xpr(1, "xrm")

    @property
    def xrt(self) -> "XXpr":
        return self.xpr(2, "xrt")

    @property
    def xxrt(self) -> "XXpr":
        return self.xpr(3, "xxrt")

    @property
    def xrt2(self) -> "XXpr":
        return self.xpr(4, "xrt2")

    @property
    def xxrt2(self) -> "XXpr":
        return self.xpr(5, "xxrt2")

    @property
    def xaddr1(self) -> "XXpr":
        return self.xpr(6, "xaddr1")

    @property
    def xaddr2(self) -> "XXpr":
        return self.xpr(7, "xaddr2")

    @property
    def is_xaddr_known(self) -> bool:
        return self.xdata.xprs_r[6] is not None

    @property
    def xaddr_updated(self) -> "XXpr":
        return self.xpr(8, "xaddr_updated")

    @property
    def annotation(self) -> str:
        wbu = self.writeback_update()
        rhs1 = self.xxrt
        rhs2 = self.xxrt2
        if self.is_ok or self.is_vmem_known:
            assign1 = str(self.vmem1) + " := " + str(rhs1)
            assign2 = str(self.vmem2) + " := " + str(rhs2)
            assigns = assign1 + "; " + assign2
        elif self.is_xaddr_known:
            assign1 = "*(" + str(self.xaddr1) + ") := " + str(rhs1)
            assign2 = "*(" + str(self.xaddr2) + ") := " + str(rhs2)
            assigns = assign1 + "; " + assign2
        else:
            assigns = "Error in vmem and xaddr"
        return self.add_instruction_condition(assigns + wbu)


@armregistry.register_tag("STRD", ARMOpcode)
class ARMStoreRegisterDual(ARMOpcode):
    """Stores words from two registers into memory.

    STRD<c> <Rt>, <Rt2>, [<Rn>,+/-<Rm>]{!}

    tags[1]: <c>
    args[0]: index of first source operand in armdictionary
    args[1]: index of second souce operand in armdictionary
    args[2]: index of base register in armdictionary
    args[3]: index of index register / immediate in armdictionary
    args[4]: index of first memory location in armdictionary
    args[5]: index of second memory location in armdictionary

    xdata format: a:vvxxxxxxxxrrrrrrddhh
    ------------------------------------
    vars[0]: lhs1
    vars[1]: lhs2
    xprs[0]: xrn (base register)
    xprs[1]: xrm (index)
    xprs[2]: xrt (rhs1, source register 1)
    xprs[3]: xxrt (rhs1, simplified)
    xprs[4]: xrt2 (rhs2, source register 2)
    xprs[5]: xxrt2 (rhs2, simplified)
    xprs[6]: lhs1 address
    xprs[7]: lhs2 address
    rdef[0]: xrn (base register)
    rdef[1]: xrm (index register)
    rdef[2]: xrt (rhs1)
    rdef[3]: xxrt (rhs1, simplified)
    rdef[4]: xrt2 (rhs2)
    rdef[5]: xxrt2 (rhs2, simplified)
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 6, "StoreRegisterDual")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1, 4]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1, 2, 3, 4, 5]]

    def memory_accesses(self, xdata: InstrXData) -> Sequence[MemoryAccess]:
        spills = self.register_spills(xdata)
        xd = ARMStoreRegisterDualXData(xdata)
        if len(spills) == 2:
            return [
                RegisterSpill(xd.xaddr1, spills[0]),
                RegisterSpill(xd.xaddr2, spills[1])]
        else:
            return [
                MemoryAccess(xd.xaddr1, "W", size=4),
                MemoryAccess(xd.xaddr2, "W", size=4)]

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def register_spills(self, xdata: InstrXData) -> List[str]:
        xd = ARMStoreRegisterDualXData(xdata)
        swaddr = xd.xaddr1
        result: List[str] = []
        if swaddr.is_stack_address:
            rhs1 = xd.xxrt
            rhs2 = xd.xxrt2
            if rhs1.is_initial_register_value:
                r1 = cast("ARMRegister", rhs1.initial_register_value_register())
                if r1.is_arm_callee_saved_register:
                    result.append(str(r1))
            if rhs2.is_initial_register_value:
                r2 = cast("ARMRegister", rhs2.initial_register_value_register())
                if r2.is_arm_callee_saved_register:
                    result.append(str(r2))
        return result

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMStoreRegisterDualXData(xdata)
        return xd.annotation

    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        (lhs1, preinstrs1, postinstrs1) = self.operands[2].ast_lvalue(astree)
        (lhs2, preinstrs2, postinstrs2) = self.operands[3].ast_lvalue(astree)
        (rhs1, _, _) = self.operands[0].ast_rvalue(astree)
        (rhs2, _, _) = self.operands[1].ast_rvalue(astree)
        assign1 = astree.mk_assign(lhs1, rhs1, iaddr=iaddr, bytestring=bytestring)
        assign2 = astree.mk_assign(lhs2, rhs2, iaddr=iaddr, bytestring=bytestring)
        return (
            preinstrs1
            + preinstrs2
            + [assign1, assign2]
            + postinstrs1
            + postinstrs2)

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        xd = ARMStoreRegisterDualXData(xdata)

        annotations: List[str] = [iaddr, "STRD"]

        # low-level assignments

        (ll_rhs1, _, _) = self.opargs[0].ast_rvalue(
            astree, iaddr=iaddr, bytestring=bytestring)
        (ll_rhs2, _, _) = self.opargs[1].ast_rvalue(
            astree, iaddr=iaddr, bytestring=bytestring)
        (ll_lhs1, ll_pre1, ll_post1) = self.opargs[4].ast_lvalue(
            astree, iaddr=iaddr, bytestring=bytestring)
        (ll_lhs2, ll_pre2, ll_post2) = self.opargs[5].ast_lvalue(
            astree, iaddr=iaddr, bytestring=bytestring)

        ll_assign1 = astree.mk_assign(
            ll_lhs1,
            ll_rhs1,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)
        ll_assign2 = astree.mk_assign(
            ll_lhs2,
            ll_rhs2,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignments

        if xd.is_ok or xd.is_vmem_known:
            lhs1 = xd.vmem1
            lhs2 = xd.vmem2
            memaddr1 = xd.xaddr1
            memaddr2 = xd.xaddr2
            hl_lhs1 = XU.xvariable_to_ast_lval(lhs1, xdata, iaddr, astree)
            hl_lhs2 = XU.xvariable_to_ast_lval(lhs2, xdata, iaddr, astree)

        elif xd.is_xaddr_known:
            memaddr1 = xd.xaddr1
            memaddr2 = xd.xaddr2
            hl_lhs1 = XU.xmemory_dereference_lval(memaddr1, xdata, iaddr, astree)
            hl_lhs2 = XU.xmemory_dereference_lval(memaddr2, xdata, iaddr, astree)

        else:
            chklogger.logger.error(
                "STRD: LHS lval and address both have error values: skipping "
                + "store-dual instruction at address %s",
                iaddr)
            return ([], [])

        rdefs = xdata.reachingdefs
        deful = xdata.defuses
        defuh = xdata.defuseshigh

        rhs1 = xd.xxrt
        rhs2 = xd.xxrt2

        hl_rhs1 = XU.xxpr_to_ast_def_expr(rhs1, xdata, iaddr, astree)
        hl_rhs2 = XU.xxpr_to_ast_def_expr(rhs2, xdata, iaddr, astree)

        hl_assign1 = astree.mk_assign(
            hl_lhs1,
            hl_rhs1,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)
        hl_assign2 = astree.mk_assign(
            hl_lhs2,
            hl_rhs2,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        if (
                (not xd.is_vmem_known)
                or (lhs1.is_memory_variable
                    and cast("VMemoryVariable", lhs1.denotation).base.is_basevar)
                or hl_lhs1.offset.is_index_offset
                or hl_lhs1.offset.is_field_offset):
            astree.add_expose_instruction(hl_assign1.instrid)
            astree.add_expose_instruction(hl_assign2.instrid)

        # TODO: add writeback update

        astree.add_instr_mapping(hl_assign1, ll_assign1)
        astree.add_instr_mapping(hl_assign2, ll_assign2)
        astree.add_instr_address(hl_assign1, [iaddr])
        astree.add_instr_address(hl_assign2, [iaddr])
        astree.add_expr_mapping(hl_rhs1, ll_rhs1)
        astree.add_expr_mapping(hl_rhs2, ll_rhs2)
        astree.add_lval_mapping(hl_lhs1, ll_lhs1)
        astree.add_lval_mapping(hl_lhs2, ll_lhs2)
        astree.add_expr_reachingdefs(ll_rhs1, [rdefs[2]])
        astree.add_expr_reachingdefs(ll_rhs2, [rdefs[4]])
        astree.add_lval_defuses(hl_lhs1, deful[0])
        astree.add_lval_defuses(hl_lhs2, deful[1])
        astree.add_lval_defuses_high(hl_lhs1, defuh[0])
        astree.add_lval_defuses_high(hl_lhs2, defuh[1])

        return ([hl_assign1, hl_assign2],
                (ll_pre1
                 + ll_pre2
                 + [ll_assign1, ll_assign2]
                 + ll_post1
                 + ll_post2))
