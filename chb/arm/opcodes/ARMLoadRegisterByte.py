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

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMOperandKind import ARMOffsetAddressOp
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr, XprCompound


class ARMLoadRegisterByteXData(ARMOpcodeXData):
    """Data format:
    - variables:
    0: vrt (lhs)

    - expressions:
    0: xrn
    1: xrm
    2: xmem (rhs)
    3: xrmem (rhs, rewritten)
    4: xaddr (address of rhs)

    - c expressions:
    0: cxrmem (rhs)
    1: cxaddr (address of rhs)
    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vrt(self) -> "XVariable":
        return self.var(0, "vrt")

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
    def is_xmem_ok(self) -> bool:
        return self.is_xpr_ok(2)

    @property
    def xrmem(self) -> "XXpr":
        return self.xpr(3, "xrmem")

    @property
    def is_xrmem_ok(self) -> bool:
        return self.is_xpr_ok(3)

    @property
    def cxrmem(self) -> "XXpr":
        return self.cxpr(0, "cxrmem")

    @property
    def is_cxrmem_ok(self) -> bool:
        return self.is_cxpr_ok(0)

    @property
    def xaddr(self) -> "XXpr":
        return self.xpr(4, "xaddr")

    @property
    def is_xaddr_ok(self) -> bool:
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
        if self.is_cxrmem_ok:
            crhs = str(self.cxrmem)
        elif self.is_cxaddr_ok:
            crhs = "*(" + str(self.cxaddr) + ")"
        else:
            crhs = "None"
        cx = " (C: " + crhs + ")"
        addr = str(self.xxaddr if self.is_xxaddr_ok else self.xaddr)
        caddr = str(self.cxaddr if self.is_cxaddr_ok else "None")
        caddr = " (addr: " + addr + "; C: " + caddr + ")"
        if self.is_ok or self.is_xrmem_ok:
            assignment = str(self.vrt) + " := " + str(self.xrmem) + cx + caddr
        elif self.is_xaddr_ok:
            assignment = (
                str(self.vrt) + " := *(" + str(self.xaddr) + ")" + cx + caddr)
        else:
            assignment = "Error value"
        return self.add_instruction_condition(assignment) + wbu


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

    xdata format:
    -------------
    rdefs[0]: reaching definitions rn
    rdefs[1]: reaching definitions rm
    rdefs[2]: reaching definitions memory location
    rdefs[3..]: reaching definitions for memory value
    uses[0]: use of lhs
    useshigh[0]: use of lhs at high level
    """

    def __init__(
            self,
            d: "ARMDictionary",
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

    def lhs(self, xdata: InstrXData) -> List[XVariable]:
        xd = ARMLoadRegisterByteXData(xdata)
        return [xd.vrt]

    def is_load_instruction(self, xdata: InstrXData) -> bool:
        return True

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        xd = ARMLoadRegisterByteXData(xdata)
        if xd.is_xrmem_ok:
            return [xd.xrmem]
        elif xd.is_xmem_ok:
            return [xd.xmem]
        else:
            return []

    def annotation(self, xdata: InstrXData) -> str:
        """lhs, rhs, with optional instr condition and base update."""

        return ARMLoadRegisterByteXData(xdata).annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        xd = ARMLoadRegisterByteXData(xdata)

        annotations: List[str] = [iaddr, "LDRB"]

        # low-level assignment

        (ll_rhs, ll_pre, ll_post) = self.opargs[3].ast_rvalue(
            astree, iaddr=iaddr, bytestring=bytestring)
        (ll_op1, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_op2, _, _) = self.opargs[2].ast_rvalue(astree)
        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignment

        def has_cast() -> bool:
            return (
                astree.has_register_variable_intro(iaddr)
                and astree.get_register_variable_intro(iaddr).has_cast())

        lhs = xd.vrt

        if xd.is_ok:
            rhs = xd.cxrmem
            rhsval = None if has_cast() else xd.cxrmem
            hl_lhs = XU.xvariable_to_ast_lval(
                lhs, xdata, iaddr, astree, rhs=rhsval)
            hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)

        elif xd.is_cxaddr_ok:
            cxaddr = xd.cxaddr
            hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)
            hl_rhs = XU.xmemory_dereference_lval_expr(
                cxaddr, xdata, iaddr, astree)

        elif xd.is_xaddr_ok:
            xaddr = xd.xaddr
            hl_lhs = XU.xvariable_to_ast_lval(lhs, xdata, iaddr, astree)
            hl_rhs = XU.xmemory_dereference_lval_expr(
                xaddr, xdata, iaddr, astree)

            chklogger.logger.warning(
                "LDRB: Unable to use a C expression for rhs. Fall back to "
                + "native byte-based address: %s to form rhs %s at address %s",
                str(xaddr), str(hl_rhs), iaddr)

        else:
            chklogger.logger.error(
                "LDRB: both memory value and address values are error values "
                + "at address %s: ", iaddr)
            return ([], (ll_pre + [ll_assign] + ll_post))

        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        if has_cast():
            astree.add_expose_instruction(hl_assign.instrid)

        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(ll_rhs, rdefs)
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        # write-back semantics

        if self.opargs[3].is_indirect_register and self.opargs[3].is_write_back:
            addrop = cast("ARMOffsetAddressOp", self.opargs[3].opkind)
            (ll_addr_lhs, _, _) = self.opargs[1].ast_lvalue(
                astree, iaddr=iaddr, bytestring=bytestring)
            ll_addr_rhs = addrop.ast_addr_rvalue(
                astree, iaddr=iaddr, bytestring=bytestring)

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

            # TODO: add writeback update

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

        return (hl_assigns, (ll_pre + ll_assigns + ll_post))
