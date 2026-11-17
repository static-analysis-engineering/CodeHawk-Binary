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

from typing import cast, List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger, CHKLogID
from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMOperandKind import ARMExtensionRegListOp
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMVectorPopXData(ARMOpcodeXData):
    """Data format:
    - variables
    0: splhs
    1..n: lhsvars

    - expressions:
    0: sprhs
    1: spresult
    2: rspresult (spresult rewritten)
    3..n+2: rrhsexprs
    n_3 .. (2n+2): xaddrs
    """

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def regcount(self) -> int:
        return len(self.xdata.vars_r) - 1

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
        return [self.xpr(i, "rhsexpr") for i in range(3, self.regcount + 3)]

    @property
    def are_rrhsexprs_ok(self) -> bool:
        return all(self.is_xpr_ok(i) for i in range(3, self.regcount + 3))

    @property
    def xaddrs(self) -> List["XXpr"]:
        return [self.xpr(i, "xaddr")
                for i in range(self.regcount + 3, (2 * self.regcount) + 3)]

    @property
    def annotation(self) -> str:
        if self.are_rrhsexprs_ok:
            pairs = zip(self.lhsvars, self.rrhsexprs)
            spassign = f"{self.splhs} := {self.rspresult}"
            assigns = "; ".join(str(v) + " := " + str(x) for (v, x) in pairs)
            assigns = f"{spassign} ; {assigns}"
        else:
            assigns = "rhs error value"
        return self.add_instruction_condition(assigns)


@armregistry.register_tag("VPOP", ARMOpcode)
class ARMVectorVectorPop(ARMOpcode):
    """Retrieves multiple consecutive extension registers from the stack.

    tags[1]: <c>
    args[0]: index of stackpointer in armdictionary
    args[1]: index of register list in armdictionary
    args[2]: index of multiple memory locations in armdictionary

    xdata format: a:vv(n)xxxx(n)rr(n)dd(n)hh(n)   (SP + registers popped)
    ---------------------------------------------------------------------
    vars[0]: SP
    vars[1..n]: v(r) for r: register popped
    xprs[0]: SP
    xprs[1]: SP updated
    xprs[2]: SP updated, simplified
    xprs[3..n+2]: x(m) for m: memory location value retrieved
    rdefs[0]: SP
    rdefs[1..n]: rdef(m) for m: memory location variable
    uses[0}: SP
    uses[1..n]: uses(r) for r: register popped
    useshigh[0]: SP
    useshigh[1..n]: useshigh(r): for r: register popped used at high level
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "VectorPop")

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
        xd = ARMVectorPopXData(xdata)
        return xd.annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        xd = ARMVectorPopXData(xdata)
        if not xd.is_ok:
            chklogger.logger.error_id(
                CHKLogID.RSLT_ERRVAL_0007,
                "VPOP: Encountered error value at address %s", iaddr)
            return ([], [])

        splhs = xd.splhs
        reglhss = xd.lhsvars
        spresult = xd.spresult
        sprresult = xd.rspresult
        memrhss = xd.rrhsexprs

        sprdef = xdata.reachingdefs[0]
        memrdefs = xdata.reachingdefs[1:]
        spuses = xdata.defuses[0]
        reguses = xdata.defuses[1:]
        spuseshigh = xdata.defuseshigh[0]
        reguseshigh = xdata.defuseshigh[1:]

        regwidth = 8 if self.is_double_precision else 4

        annotations: List[str] = [iaddr, "VPOP"]

        # low-level assignments

        (splval, _, _) = self.opargs[0].ast_lvalue(astree)
        (sprval, _, _) = self.opargs[0].ast_rvalue(astree)

        ll_instrs: List[AST.ASTInstruction] = []
        hl_instrs: List[AST.ASTInstruction] = []

        regsop = self.opargs[1]
        registers = regsop.extension_registers
        sp_offset = 0

        for (i, r) in enumerate(registers):
            sp_offset_c = astree.mk_integer_constant(sp_offset)
            addr = astree.mk_binary_op("plus", sprval, sp_offset_c)
            ll_lhs = astree.mk_variable_lval(str(r))
            ll_rhs = astree.mk_memref_expr(addr)
            ll_assign = astree.mk_assign(
                ll_lhs,
                ll_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            ll_instrs.append(ll_assign)

            # high-level assignments

            lhs = reglhss[i]
            rhs = memrhss[i]

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
            astree.add_expr_reachingdefs(ll_rhs, [memrdefs[i]])
            astree.add_lval_defuses(hl_lhs, reguses[i])
            astree.add_lval_defuses_high(hl_lhs, reguseshigh[i])

        sp_offset += regwidth

        # low-level SP assignment

        ll_sp_lhs = splval
        sp_incr = regwidth * len(registers)
        sp_incr_c = astree.mk_integer_constant(sp_incr)
        ll_sp_rhs = astree.mk_binary_op("plus", sprval, sp_incr_c)
        ll_sp_assign = astree.mk_assign(
            ll_sp_lhs,
            ll_sp_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)
        ll_instrs.append(ll_sp_assign)

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
        astree.add_expr_reachingdefs(ll_sp_rhs, [sprdef])
        astree.add_lval_defuses(hl_sp_lhs, spuses)
        astree.add_lval_defuses_high(hl_sp_lhs, spuseshigh)

        return (hl_instrs, ll_instrs)
