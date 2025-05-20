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

from typing import List, Tuple, TYPE_CHECKING

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

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMVLoadRegisterXData(ARMOpcodeXData):
    """
    Data format:
    - variables
    0: vvd
    1: vmem

    - expressions:
    0: xmem
    1: rxmem
    2: xbase
    3: rxbase
    4: xaddr
    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def vvd(self) -> "XVariable":
        return self.var(0, "vvd")

    @property
    def is_vvd_ok(self) -> bool:
        return self.is_var_ok(0)

    @property
    def vmem(self) -> "XVariable":
        return self.var(1, "vmem")

    @property
    def is_vmem_ok(self) -> bool:
        return self.is_var_ok(1)

    @property
    def xmem(self) -> "XXpr":
        return self.xpr(0, "xmem")

    @property
    def is_xmem_ok(self) -> bool:
        return self.is_xpr_ok(0)

    @property
    def rxmem(self) -> "XXpr":
        return self.xpr(1, "rxmem")

    @property
    def is_rxmem_ok(self) -> bool:
        return self.is_xpr_ok(1)

    @property
    def xbase(self) -> "XXpr":
        return self.xpr(2, "xbase")

    @property
    def is_xbase_ok(self) -> bool:
        return self.is_xpr_ok(2)

    @property
    def rxbase(self) -> "XXpr":
        return self.xpr(3, "rxbase")

    @property
    def is_rxbase_ok(self) -> bool:
        return self.is_xpr_ok(3)

    @property
    def xaddr(self) -> "XXpr":
        return self.xpr(4, "xaddr")

    @property
    def is_xaddr_ok(self) -> bool:
        return self.is_xpr_ok(4)

    @property
    def annotation(self) -> str:
        lhs = str(self.vvd) if self.is_vvd_ok else "?"
        rhs = str(self.rxmem) if self.is_rxmem_ok else "?"
        assign = lhs + " := " + rhs
        return self.add_instruction_condition(assign)


@armregistry.register_tag("VLDR", ARMOpcode)
class ARMVLoadRegister(ARMOpcode):
    """Loads a single extension register from memory

    VLDR<c> <Dd>, [<Rn>{, #+/-<imm>}]
    VLDR<c> <Sd>, [<Rn>{, #+/-<imm>}]

    tags[1]: <c>
    args[0]: index of Dd/Sd in armdictionary
    args[1]: index of Rn in armdictionary
    args[2]: index of memory location in armdictionary

    xdata format: a:vvxxxrrrdh
    --------------------------
    vars[0]: lhs
    vars[1]: memory location expressed as a variable
    xprs[0]: value in memory location
    xprs[1]: value in memory location rewritten
    xprs[2]: value in base register
    xprs[3]: value in base register rewritten
    xprs[4]: address of memory location
    rdefs[0]: reaching definition memory value
    rdefs[1]: reaching definition base register
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "VStore")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 2]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1, 2]]

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMVLoadRegisterXData(xdata)
        return xd.annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VLDR"]

        (ll_rhs, ll_preinstrs, ll_postinstrs) = self.opargs[2].ast_rvalue(astree)
        (ll_op1, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        lhs = xdata.vars[0]
        rhs = xdata.xprs[1]
        memaddr = xdata.xprs[2]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_preinstrs: List[AST.ASTInstruction] = []
        hl_postinstrs: List[AST.ASTInstruction] = []

        rhsexprs = XU.xxpr_to_ast_exprs(rhs, xdata, iaddr, astree)
        if len(rhsexprs) == 0:
            raise UF.CHBError(
                "VLoadRegister (VLDR): no rhs value found")

        if len(rhsexprs) > 1:
            raise UF.CHBError(
                "VLoadRegister (VLDR): multiple rhs values: "
                + ", ".join(str(x) for x in rhsexprs))

        hl_rhs = rhsexprs[0]
        if str(hl_rhs).startswith("__asttmp"):
            addrlval = XU.xmemory_dereference_lval(memaddr, xdata, iaddr, astree)
            hl_rhs = astree.mk_lval_expression(addrlval)

        # hl_lhs = astree.mk_register_variable_lval(str(lhs))
        hl_lhs = XU.xvariable_to_ast_lvals(lhs, xdata, astree)[0]
        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_reg_definition(iaddr, hl_lhs, hl_rhs)
        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(hl_rhs, [rdefs[0]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        return ([hl_assign], [ll_assign])
