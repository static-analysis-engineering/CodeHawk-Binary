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

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XprCompound, XprConstant, XXpr


class ARMVStoreRegisterXData(ARMOpcodeXData):
    """
    Data format:
    - variables
    0: vmem

    - c variables:
    0: cvmem

    - expressions:
    0: xsrc
    1: rxsrc
    2: xbase
    3: rxbase
    4: xaddr
    5: xxaddr
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
    def xsrc(self) -> "XXpr":
        return self.xpr(0, "xsrc")

    @property
    def rxsrc(self) -> "XXpr":
        return self.xpr(1, "rxsrc")

    @property
    def xbase(self) -> "XXpr":
        return self.xpr(2, "xbase")

    @property
    def rxbase(self) -> "XXpr":
        return self.xpr(3, "rxbase")

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
    def cxaddr(self) -> "XXpr":
        return self.cxpr(1, "cxaddr")

    @property
    def is_cxaddr_ok(self) -> bool:
        return self.is_cxpr_ok(1)

    @property
    def is_xxaddr_ok(self) -> bool:
        return self.is_xpr_ok(5)

    @property
    def annotation(self) -> str:
        clhs = str(self.cvmem) if self.is_cvmem_ok else "None"
        assignc = "(C: " + clhs + " := " + str(self.rxsrc) + ")"
        if self.is_vmem_ok:
            lhs = str(self.vmem)
        elif self.is_xxaddr_ok:
            lhs = "*(" + str(self.xxaddr) + ")"
        elif self.is_xaddr_ok:
            lhs = "*(" + str(self.xaddr) + ")"
        else:
            lhs = "Error addr"
        rhs = str(self.rxsrc)
        assign = lhs + " := " + rhs + " " + assignc
        return self.add_instruction_condition(assign)


@armregistry.register_tag("VSTR", ARMOpcode)
class ARMVStoreRegister(ARMOpcode):
    """Stores a single extension register to memory

    VSTR<c> <Dd>, [<Rn>{, #+/-<imm>}]
    VSTR<c> <Sd>, [<Rn>{, #+/-<imm>}]

    tags[1]: <c>
    args[0]: index of Dd/Sd in armdictionary
    args[1]: index of Rn in armdictionary
    args[2]: index of memory location in armdictionary

    xdata:
    ------------------------
    rdefs[0]: reaching def of src expression
    rdefs[1]: reaching def of base expression
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "VStore")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 2]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1, 2]]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMVStoreRegisterXData(xdata)
        return xd.annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VSTR"]

        # low-level assignment

        (ll_rhs, _, _) = self.opargs[0].ast_rvalue(
            astree, iaddr=iaddr, bytestring=bytestring)
        (ll_lhs, ll_preinstrs, ll_postinstrs) = self.opargs[2].ast_lvalue(
            astree, iaddr=iaddr, bytestring=bytestring)
        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        # high-level assignment

        xd = ARMVStoreRegisterXData(xdata)

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
                "VSTR: Lhs lval and address both have error values: skipping "
                "vstore instruction at address %s", iaddr)
            return ([], (ll_preinstrs + [ll_assign] + ll_postinstrs))

        rhs = xd.rxsrc
        xaddr = xd.xaddr
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_rhs = XU.xxpr_to_ast_def_expr(rhs, xdata, iaddr, astree)

        hl_preinstrs: List[AST.ASTInstruction] = []
        hl_postinstrs: List[AST.ASTInstruction] = []

        hl_rhs_type = hl_rhs.ctype(astree.ctyper)

        astree.add_lval_store(hl_lhs)

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
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[1]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        if ll_lhs.lhost.is_memref:
            memexp = cast(AST.ASTMemRef, ll_lhs.lhost).memexp
            astree.add_expr_reachingdefs(memexp, [rdefs[0]])

        return ([hl_assign], (ll_preinstrs + [ll_assign] + ll_postinstrs))
