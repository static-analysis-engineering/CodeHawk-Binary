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
    from chb.arm.ARMRegister import ARMRegister
    from chb.invariants.VAssemblyVariable import VAuxiliaryVariable, VMemoryVariable
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

    xdata format: a:vxxxxrrrdh
    --------------------------
    vars[0]: lhs
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
    useshigh[0]: lhs
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

        xctr = 4
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

        (ll_rhs, _, _) = self.opargs[0].ast_rvalue(astree)
        (ll_lhs, ll_preinstrs, ll_postinstrs) = self.opargs[3].ast_lvalue(astree)
        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        lhs = xdata.vars[0]
        rhs = xdata.xprs[3]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_preinstrs: List[AST.ASTInstruction] = []
        hl_postinstrs: List[AST.ASTInstruction] = []

        if rhs.is_register_variable:
            rhsexprs = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)
        else:
            rhsexprs = XU.xxpr_to_ast_exprs(rhs, xdata, astree)

        if len(rhsexprs) == 0:
            raise UF.CHBError("No rhs for StoreRegister (STR) at " + iaddr)

        if len(rhsexprs) > 1:
            raise UF.CHBError(
                "Multiple rhs values for StoreRegister (STR) at "
                + iaddr
                + ": "
                + ", ".join(str(x) for x in rhsexprs))

        hl_rhs = rhsexprs[0]

        def split_assigns(
                base: AST.ASTLvalExpr,
                offsets: List[AST.ASTExpr],
                rhs: AST.ASTLvalExpr) -> Tuple[List[
                    AST.ASTInstruction], List[AST.ASTInstruction]]:

            hl_assigns: List[AST.ASTInstruction] = []
            for i in range(0, 4):
                ioffset = cast(AST.ASTExpr, astree.mk_integer_constant(i))
                offsetsi = [ioffset] + offsets[:]
                newoffseti = astree.add_index_list_offset(
                    base.lval.offset, offsetsi)
                hl_mem_lhsi = astree.mk_lval(base.lval.lhost, newoffseti)
                newoffseti = astree.add_to_index_offset(rhs.lval.offset, i)
                rhsi_lval = astree.mk_lval(rhs.lval.lhost, newoffseti)
                rhsi = astree.mk_lval_expression(rhsi_lval)

                hl_assigni = astree.mk_assign(
                    hl_mem_lhsi,
                    rhsi,
                    iaddr=iaddr,
                    bytestring=bytestring,
                    annotations=annotations)

                astree.add_instr_mapping(hl_assigni, ll_assign)
                astree.add_expr_mapping(rhsi, ll_rhs)
                astree.add_lval_mapping(hl_mem_lhsi, ll_lhs)
                astree.add_expr_reachingdefs(ll_rhs, [rdefs[2]])
                astree.add_lval_defuses(hl_mem_lhsi, defuses[0])
                astree.add_lval_defuses_high(hl_mem_lhsi, defuseshigh[0])

                astree.add_lval_store(hl_mem_lhsi)
                hl_assigns.append(hl_assigni)

            return (hl_assigns, [ll_assign])

        if lhs.is_tmp or lhs.has_unknown_memory_base():
            hl_lhs = None
            address = xdata.xprs[4]
            astaddrs = XU.xxpr_to_ast_def_exprs(address, xdata, iaddr, astree)
            if len(astaddrs) == 1:
                astaddr = astaddrs[0]
                if astaddr.is_ast_addressof:
                    hl_lhs = cast(AST.ASTAddressOf, astaddr).lval
                else:
                    astaddrtype = astaddr.ctype(astree.ctyper)
                    if astaddrtype is not None:
                        if astaddrtype.is_pointer:
                            astaddrtype = cast(AST.ASTTypPtr, astaddrtype)
                            astaddrtgttype = astaddrtype.tgttyp
                            if astree.type_size_in_bytes(astaddrtgttype) == 1:
                                if astaddr.is_ast_binary_op:
                                    (base, offsets) = astree.split_address_int_offset(astaddr)
                                    if base.is_ast_lval_expr and hl_rhs.is_ast_lval_expr:
                                        base = cast(AST.ASTLvalExpr, base)
                                        hl_rhs = cast(AST.ASTLvalExpr, hl_rhs)
                                        return split_assigns(base, offsets, hl_rhs)

            if hl_lhs is None:
                hl_lhs = XU.xmemory_dereference_lval(xdata.xprs[4], xdata, iaddr, astree)
            astree.add_lval_store(hl_lhs)

        else:
            lvals = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
            if len(lvals) == 0:
                raise UF.CHBError(
                    "No lhs value for StoreRegister (STR) at " + iaddr)

            if len(lvals) > 1:
                raise UF.CHBError(
                    "Multiple lhs values for StoreRegister (STR) at "
                    + iaddr
                    + ": "
                    + ", ".join(str(x) for x in lvals))

            hl_lhs = lvals[0]

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[2]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        if ll_lhs.lhost.is_memref:
            memexp = cast(AST.ASTMemRef, ll_lhs.lhost).memexp
            astree.add_expr_reachingdefs(memexp, [rdefs[0], rdefs[1]])

        return ([hl_assign], (ll_preinstrs + [ll_assign] + ll_postinstrs))
