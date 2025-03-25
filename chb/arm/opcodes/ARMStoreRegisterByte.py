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

from typing import cast, List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMOperandKind import ARMOffsetAddressOp
    from chb.invariants.VAssemblyVariable import VMemoryVariable
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMStoreRegisterByteXData(ARMOpcodeXData):
    """Data format:
    - variables:
    0: vmem_r (lhs)

    - c variables:
    0: cvmem_r (lhs)

    - expressions:
    0: xrn
    1: xrm
    2: xrt (rhs)
    3: xxrt (rhs, rewritten)
    4: xaddr (lhs address)
    5: xxaddr (lhs address, rewritten)

    - c expressions:
    0: cxrt (rhs)
    1: cxaddr (lhs address)
    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vmem(self) -> "XVariable":
        return self.var(0, "vmem")

    @property
    def is_vmem_ok(self) -> bool:
        return self.is_var_ok(0)

    @property
    def cvmem(self) -> "XVariable":
        return self.cvar(0, "cvmem")

    @property
    def is_cvmem_ok(self) -> bool:
        return self.is_cvar_ok(0)

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
    def is_xxrt_ok(self) -> bool:
        return self.is_xpr_ok(3)

    @property
    def cxrt(self) -> "XXpr":
        return self.cxpr(0, "cxrt")

    @property
    def is_cxrt_ok(self) -> bool:
        return self.is_cxpr_ok(0)

    @property
    def xaddr(self) -> "XXpr":
        return self.xpr(4, "xaddr")

    @property
    def is_xaddr_ok(self) -> "bool":
        return self.is_xpr_ok(4)

    @property
    def xxaddr(self) -> "XXpr":
        return self.xpr(5, "xxaddr")

    @property
    def is_xxaddr_ok(self) -> bool:
        return self.is_xpr_ok(5)

    @property
    def cxaddr(self) -> "XXpr":
        return self.cxpr(1, "cxaddr")

    @property
    def is_cxaddr_ok(self) -> bool:
        return self.is_cxpr_ok(1)

    @property
    def annotation(self) -> str:
        wbu = self.writeback_update()
        clhs = str(self.cvmem) if self.is_cvmem_ok else "None"
        crhs = str(self.cxrt) if self.is_cxrt_ok else "None"
        assignc = "(C: " + clhs + " := " + crhs + ")"
        if self.is_vmem_ok:
            lhs = str(self.vmem)
        elif self.is_xxaddr_ok:
            lhs = "*(" + str(self.xxaddr) + ")"
        elif self.is_xaddr_ok:
            lhs = "*(" + str(self.xaddr) + ")"
        else:
            lhs = "Error addr"
        if self.is_xxrt_ok:
            rhs = str(self.xxrt)
        else:
            rhs = "Error value"
        assign = lhs + " := " + rhs
        assignment = assign + " " + assignc
        return self.add_instruction_condition(assignment + wbu)


@armregistry.register_tag("STRB", ARMOpcode)
class ARMStoreRegisterByte(ARMOpcode):
    """Stores the least significant byte from a register into memory.

    STRB<c> <Rt>, [<base>, <offset>]

    tags[1]: <c>
    args[0]: index of source operand in armdictionary
    args[1]: index of base register in armdictionary
    args[2]: index of index in armdictionary
    args[3]: index of memory location in armdictionary
    args[4]: is-wide (thumb)

    xdata format:
    -------------
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
        self.check_key(2, 5, "StoreRegisterByte")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 3]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[4] == 1 else ""
        return cc + wide

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1, 2, 3]]

    @property
    def membase_operand(self) -> ARMOperand:
        return self.opargs[1]

    @property
    def memindex_operand(self) -> ARMOperand:
        return self.opargs[2]

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        return ARMStoreRegisterByteXData(xdata).annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "STRB"]

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

        xd = ARMStoreRegisterByteXData(xdata)

        if xd.is_cvmem_ok:
            lhs = xd.cvmem
            hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)

        elif xd.is_vmem_ok:
            lhs = xd.vmem
            hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)

        elif xd.is_cxaddr_ok:
            memaddr = xd.cxaddr
            hl_lhs = XU.xmemory_dereference_lval(memaddr, xdata, iaddr, astree)

        elif xd.is_xxaddr_ok:
            memaddr = xd.xxaddr
            hl_lhs = XU.xmemory_dereference_lval(memaddr, xdata, iaddr, astree)

        elif xd.is_xaddr_ok:
            memaddr = xd.xaddr
            hl_lhs = XU.xmemory_dereference_lval(memaddr, xdata, iaddr, astree)

        else:
            chklogger.logger.error(
                "STRB: Lhs lval and address both have error values: skipping "
                "store instruction at address %s", iaddr)
            return ([], (ll_preinstrs + [ll_assign] + ll_postinstrs))

        if xd.is_cxrt_ok:
            rhs = xd.cxrt
        elif xd.is_xxrt_ok:
            rhs = xd.xxrt
        else:
            rhs = xd.xrt
        hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)

        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

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
                (not xd.is_vmem_ok)
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

        return ([hl_assign], (ll_preinstrs + ll_assigns + ll_postinstrs))
