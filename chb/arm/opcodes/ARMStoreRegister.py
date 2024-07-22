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

from typing import cast, List, Sequence, Optional, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData
from chb.app.MemoryAccess import MemoryAccess, RegisterSpill

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XXpr, XprCompound, XprVariable
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMOperandKind import ARMOffsetAddressOp
    from chb.arm.ARMRegister import ARMRegister
    from chb.invariants.VAssemblyVariable import (
        VAuxiliaryVariable, VMemoryVariable)
    from chb.invariants.VConstantValueVariable import VInitialRegisterValue
    from chb.invariants.XXpr import XprVariable


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
        if spill is not None:
            return [RegisterSpill(xdata.xprs[4], spill)]
        else:
            return [MemoryAccess(xdata.xprs[4], "W", size=4)]

    @property
    def membase_operand(self) -> ARMOperand:
        return self.opargs[1]

    @property
    def memindex_operand(self) -> ARMOperand:
        return self.opargs[2]

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def register_spill(self, xdata: InstrXData) -> Optional[str]:
        swaddr = xdata.xprs[4]
        if swaddr.is_stack_address:
            rhs = xdata.xprs[3]
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
        lhs = xdata.vars[0]
        rhs = xdata.xprs[3]
        if rhs.is_function_return_value:
            rhsp = str(rhs.variable.denotation)
        else:
            rhsp = str(rhs)
        assign = str(lhs) + " := " + rhsp

        xctr = 5
        if xdata.has_instruction_condition():
            pcond = "if " + str(xdata.xprs[xctr]) + " then "
            xctr += 1
        elif xdata.has_unknown_instruction_condition():
            pcond = "if ? then "
        else:
            pcond = ""

        return pcond + assign

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

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

        lhs = xdata.vars[0]
        rhs = xdata.xprs[3]
        memaddr = xdata.xprs[4]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)
        hl_lhs = XU.xvariable_to_ast_lval(
            lhs, xdata, iaddr, astree, memaddr=memaddr)

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        if lhs.is_tmp:
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

            basereg = xdata.vars[1]
            newaddr = xdata.xprs[4]
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
