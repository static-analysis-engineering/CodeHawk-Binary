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

from typing import cast, List, Sequence, Optional, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData
from chb.app.MemoryAccess import MemoryAccess, RegisterSpill

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XXpr, XprCompound, XprConstant, XprVariable
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMOperandKind import ARMOffsetAddressOp
    from chb.arm.ARMRegister import ARMRegister
    from chb.invariants.VAssemblyVariable import (
        VAuxiliaryVariable, VMemoryVariable)
    from chb.invariants.VConstantValueVariable import VInitialRegisterValue
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XprVariable


class ARMStoreRegisterXData(ARMOpcodeXData):

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vmem(self) -> "XVariable":
        return self.var(0, "vmem")

    @property
    def is_vmem_unknown(self) -> bool:
        return self.xdata.vars_r[0] is None

    @property
    def vrn(self) -> "XVariable":
        return self.var(1, "vrn")

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
    def xaddr(self) -> "XXpr":
        return self.xpr(4, "xaddr")

    @property
    def is_address_known(self) -> bool:
        return self.xdata.xprs_r[4] is not None

    @property
    def xaddr_updated(self) -> "XXpr":
        return self.xpr(5, "xaddr_updated")

    @property
    def annotation(self) -> str:
        wbu = self.writeback_update()
        if self.is_ok:
            assignment = str(self.vmem) + " := " + str(self.xxrt)
        elif self.is_vmem_unknown and self.is_address_known:
            assignment = "*(" + str(self.xaddr) + ") := " + str(self.xxrt)
        else:
            assignment = "Error value"
        return self.add_instruction_condition(assignment + wbu)


@armregistry.register_tag("STR", ARMOpcode)
class ARMStoreRegister(ARMOpcode):
    """Stores a word from a register into memory.

    STR<c> <Rt>, [<base>, <offset>]

    tags[1]: <c>
    args[0]: index of source operand in armdictionary
    args[1]: index of base register in armdictionary
    args[2]: index of index in armdictionary
    args[3]: index of memory location in armdictionary
    args[4]: is-wide (thumb)

    xdata format
    ------------
    vars[0]: lhs
    vars[1]: vrn (base register, only if writeback)
    xprs[0]: xrn (base register)
    xprs[1]: xrm (index)
    xprs[2]: xrt (rhs, source register)
    xprs[3]: xrt (rhs, simplified)
    xprs[4]: address of memory location
    xprs[5]: condition (if TC is set)
    rdefs[0]: rn
    rdefs[1]: rm
    rdefs[2]: rt
    uses[0]: lhs
    uses[1]: vrn (base register, only if writeback)
    useshigh[0]: lhs
    useshigh[1]: vrn (base register, only if writeback)
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "StoreRegister")

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

    @property
    def is_write_back(self) -> bool:
        return self.opargs[3].is_write_back

    def memory_accesses(self, xdata: InstrXData) -> Sequence[MemoryAccess]:
        spill = self.register_spill(xdata)
        xd = ARMStoreRegisterXData(xdata)
        if spill is not None:
            return [RegisterSpill(xd.xaddr, spill)]
        else:
            return [MemoryAccess(xd.xaddr, "W", size=4)]

    @property
    def membase_operand(self) -> ARMOperand:
        return self.opargs[1]

    @property
    def memindex_operand(self) -> ARMOperand:
        return self.opargs[2]

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def register_spill(self, xdata: InstrXData) -> Optional[str]:
        xd = ARMStoreRegisterXData(xdata)
        swaddr = xd.xaddr
        if swaddr.is_stack_address:
            rhs = xd.xxrt
            if rhs.is_var:
                rhsv = cast("XprVariable", rhs).variable
                if rhsv.denotation.is_auxiliary_variable:
                    v = cast("VAuxiliaryVariable", rhsv.denotation)
                    if v.auxvar.is_initial_register_value:
                        vx = cast("VInitialRegisterValue", v.auxvar)
                        r = cast("ARMRegister", vx.register)
                        if r.is_arm_callee_saved_register:
                            return str(r)
        return None

    def annotation(self, xdata: InstrXData) -> str:
        return ARMStoreRegisterXData(xdata).annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        xd = ARMStoreRegisterXData(xdata)
        annotations: List[str] = [iaddr, "STR"]

        # low-level assignment

        (ll_rhs, _, _) = self.opargs[0].ast_rvalue(astree)
        (ll_lhs, ll_preinstrs, ll_postinstrs) = self.opargs[3].ast_lvalue(astree)
        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignment

        if xd.is_ok:
            lhs = xd.vmem
            memaddr = xd.xaddr
            hl_lhs = XU.xvariable_to_ast_lval(
                lhs, xdata, iaddr, astree, memaddr=memaddr)

        elif xd.is_vmem_unknown and xd.is_address_known:
            memaddr = xd.xaddr
            hl_lhs = XU.xmemory_dereference_lval(memaddr, xdata, iaddr, astree)

        else:
            chklogger.logger.error(
                "STR: Lhs lval and address both have error values: skipping "
                "store instruction at address %s",
                iaddr)
            return ([], [])

        rhs = xd.xxrt
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)

        if rhs.is_string_reference:
            rhsval = cast(XprConstant, rhs).intvalue
            saddr = hex(rhsval)
            cstr = rhs.constant.string_reference()
            hl_rhs = astree.mk_string_constant(hl_rhs, cstr, saddr)

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # Currently def-use info does not properly account for assignments
        # to variables that are part of a struct or array variable, so these
        # assignments must be explicitly forced to appear in the lifting
        if (
                xd.is_vmem_unknown
                or hl_lhs.offset.is_index_offset
                or hl_lhs.offset.is_field_offset):
            astree.add_expose_instruction(hl_assign.instrid)

        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[2]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        # add optional write-back

        if self.opargs[3].is_indirect_register and self.opargs[3].is_write_back:
            addrop = cast("ARMOffsetAddressOp", self.opargs[3].opkind)
            (ll_addr_lhs, _, _) = self.opargs[1].ast_lvalue(astree)
            ll_addr_rhs = addrop.ast_addr_rvalue(astree)

            ll_addr_assign = astree.mk_assign(
                ll_addr_lhs,
                ll_addr_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            ll_assigns: List[AST.ASTInstruction] = [ll_assign, ll_addr_assign]

            basereg = xd.get_base_update_var()
            newaddr = xd.get_base_update_xpr()
            hl_addr_lhs = XU.xvariable_to_ast_lval(basereg, xdata, iaddr, astree)
            hl_addr_rhs = XU.xxpr_to_ast_def_expr(newaddr, xdata, iaddr, astree)

            hl_addr_assign = astree.mk_assign(
                hl_addr_lhs,
                hl_addr_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            hl_assigns: List[AST.ASTInstruction] = [hl_assign, hl_addr_assign]

            astree.add_instr_mapping(hl_addr_assign, ll_addr_assign)
            astree.add_instr_address(hl_addr_assign, [iaddr])
            astree.add_expr_mapping(hl_addr_rhs, ll_addr_rhs)
            astree.add_lval_mapping(hl_addr_lhs, ll_addr_lhs)
            astree.add_expr_reachingdefs(ll_addr_rhs, [rdefs[0]])
            astree.add_lval_defuses(ll_addr_lhs, defuses[1])
            astree.add_lval_defuses_high(ll_addr_lhs, defuseshigh[1])
        else:
            ll_assigns = [ll_assign]
            hl_assigns = [hl_assign]

        if ll_lhs.lhost.is_memref:
            memexp = cast(AST.ASTMemRef, ll_lhs.lhost).memexp
            astree.add_expr_reachingdefs(memexp, [rdefs[0], rdefs[1]])

        return (hl_assigns, (ll_preinstrs + ll_assigns + ll_postinstrs))
