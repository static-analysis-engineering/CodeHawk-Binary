# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2026 Aarno Labs LLC
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

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData
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
    from chb.arm.ARMOperandKind import ARMExtensionRegListOp
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMVectorPushXData(ARMOpcodeXData):

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
        splhs = self.splhs
        spresult = self.rspresult
        spassign = f"{splhs} := {spresult}"
        assigns = ";  ".join(str(v) + " := " + str(x) for (v, x) in pairs)
        assigns = spassign + "; " + assigns
        return self.add_instruction_condition(assigns)


@armregistry.register_tag("VPUSH", ARMOpcode)
class ARMVectorPush(ARMOpcode):
    """Stores multiple consecutive extension registers to the stack.

    tags[1]: <c>
    args[0]: index of stackpointer in armdictionary
    args[1]: index of register list in armdictionary
    args[2]: index of multiple memory locations in armdictionary

    xdata format: a:vv(n)xxxx(n)x(n)dd(n)hh(n)  (SP + registers pushed)
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

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "VectorPush")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[1])]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1]]

    @property
    def extension_register_list_op(self) -> "ARMExtensionRegListOp":
        return cast("ARMExtensionRegListOp", self.opargs[1].opkind)

    @property
    def register_count(self) -> int:
        return self.extension_register_list_op.count

    @property
    def is_double_precision(self) -> bool:
        return self.extension_register_list_op.is_double_precision

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMVectorPushXData(xdata)
        return xd.annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        xd = ARMVectorPushXData(xdata)
        if not xd.is_ok:
            chklogger.logger.error(
                "VPUSH: Encountered error value at address %s", iaddr)
            return ([], [])

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

        regwidth = 8 if self.is_double_precision else 4

        annotations: List[str] = [iaddr, "VPUSH"]

        # low-level assignments

        (splval, _, _) = self.opargs[0].ast_lvalue(astree)
        (sprval, _, _) = self.opargs[0].ast_rvalue(astree)

        ll_instrs: List[AST.ASTInstruction] = []
        hl_instrs: List[AST.ASTInstruction] = []

        regsop = self.opargs[1]
        registers = regsop.extension_registers
        sp_decr = regwidth * len(registers)
        sp_offset = sp_decr

        for (i, r) in enumerate(registers):
            sp_offset_c = astree.mk_integer_constant(sp_offset)
            addr = astree.mk_binary_op("minus", sprval, sp_offset_c)
            ll_lhs = astree.mk_memref_lval(addr)
            ll_rhs = astree.mk_register_variable_expr(str(r))
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

            sp_offset -= regwidth

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
        astree.add_lval_defuses(hl_sp_lhs, spuses)
        astree.add_lval_defuses_high(hl_sp_lhs, spuseshigh)

        return (hl_instrs, ll_instrs)
