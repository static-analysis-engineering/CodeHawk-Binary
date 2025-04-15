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

from typing import cast, List, Optional, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
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
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMPopXData(ARMOpcodeXData):
    """Data format:
    - variables:
    0: splhs
    1..n: lhsvars

    - expressions:
    0: sprhs
    1: spresult
    2: rspresult (spresult, rewritten)
    3..n+2: rrhsexprs
    n+3 .. (2n+2): xaddrs

    optional return values:
    - returnval
    - rreturnval
    - creturnval
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

    def has_return_xpr(self) -> bool:
        return self.xdata.has_return_xpr()

    def returnval(self) -> "XXpr":
        return self.xdata.get_return_xpr()

    def rreturnval(self) -> "XXpr":
        return self.xdata.get_return_xxpr()

    def has_creturnval(self) -> bool:
        return self.xdata.has_return_cxpr()

    def creturnval(self) -> "XXpr":
        return self.xdata.get_return_cxpr()

    @property
    def r0(self) -> Optional["XXpr"]:
        if "return" in self._xdata.tags:
            return self.xpr((2 * self.regcount) + 3, "r0")
        return None

    @property
    def annotation(self) -> str:
        if self.are_rrhsexprs_ok:
            pairs = zip(self.lhsvars, self.rrhsexprs)
            spassign = str(self.splhs) + " := " + str(self.rspresult)
            assigns = "; ".join(str(v) + " := " + str(x) for (v, x) in pairs)
            assigns = spassign + "; " + assigns
            if self.has_return_xpr():
                cxpr = (
                    " (C: "
                    + (str(self.creturnval()) if self.has_creturnval() else "None")
                    + ")")
                rxpr = "; return " + str(self.rreturnval()) + cxpr
            else:
                rxpr = ""
        else:
            assigns = "rhs error value"
            rxpr = "?"
        return self.add_instruction_condition(assigns + rxpr)


@armregistry.register_tag("POP", ARMOpcode)
class ARMPop(ARMOpcode):
    """Loads multiple registers from the stack, and updates the stackpointer.

    POP<c> <registers>

    tags[1]: <c>
    args[0]: index of stackpointer operand in armdictionary
    args[1]: index of register list in armdictionary
    args[2]: is-wide (thumb)

    xdata format
    ------------
    rdefs[0]: SP
    rdefs[1..n]: rdef(m) for m: memory location variable
    rdefs[n+1]: (optional) rdef for R0 if register list includes PC
    uses[0}: SP
    uses[1..n]: uses(r) for r: register popped
    useshigh[0]: SP
    useshigh[1..n]: useshigh(r): for r: register popped used at high level
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 3, "Pop")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[2] == 1 else ""
        return cc + wide

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1]]

    @property
    def operandstring(self) -> str:
        return str(self.operands[1])

    def is_return_instruction(self, xdata: InstrXData) -> bool:
        return ARMPopXData(xdata).has_return_xpr()

    def return_value(self, xdata: InstrXData) -> Optional[XXpr]:
        xd = ARMPopXData(xdata)
        if xd.has_return_xpr():
            if xd.has_creturnval():
                return xd.creturnval()
            else:
                return xd.rreturnval()
        else:
            return None

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMPopXData(xdata)
        return xd.annotation

    def ast_condition_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData,
            reverse: bool
    ) -> Tuple[Optional[AST.ASTExpr], Optional[AST.ASTExpr]]:

        ll_astcond = self.ast_cc_expr(astree)

        if xdata.has_instruction_condition():
            if reverse:
                pcond = xdata.xprs[(2 * len(xdata.vars)) + 3]
            else:
                pcond = xdata.xprs[(2 * len(xdata.vars)) + 2]
            hl_astcond = XU.xxpr_to_ast_def_expr(pcond, xdata, iaddr, astree)

            astree.add_expr_mapping(hl_astcond, ll_astcond)
            astree.add_expr_reachingdefs(hl_astcond, xdata.reachingdefs)
            astree.add_flag_expr_reachingdefs(ll_astcond, xdata.flag_reachingdefs)
            astree.add_condition_address(ll_astcond, [iaddr])

            return (hl_astcond, ll_astcond)

        else:
            chklogger.logger.error(
                "No condition found at address %s", iaddr)
            hl_astcond = astree.mk_temp_lval_expression()
            return (hl_astcond, ll_astcond)

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        xd = ARMPopXData(xdata)
        if not xd.is_ok:
            chklogger.logger.error(
                "Encountered error value at address %s", iaddr)
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

        annotations: List[str] = [iaddr, "POP"]

        # low-level assignments

        (splval, _, _) = self.opargs[0].ast_lvalue(astree)
        (sprval, _, _) = self.opargs[0].ast_rvalue(astree)

        ll_instrs: List[AST.ASTInstruction] = []
        hl_instrs: List[AST.ASTInstruction] = []
        regsop = self.opargs[1]
        registers = regsop.registers
        sp_offset = 0
        for (i, r) in enumerate(registers):
            sp_offset_c = astree.mk_integer_constant(sp_offset)
            addr = astree.mk_binary_op("plus", sprval, sp_offset_c)
            ll_lhs = astree.mk_variable_lval(r)
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

            if astree.is_in_wrapper(iaddr):
                chklogger.logger.info(
                    "Skip restore of %s at %s within trampoline wrapper",
                    str(lhs), iaddr)

            else:
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

            sp_offset += 4

        # low-level SP assignment

        ll_sp_lhs = splval
        sp_incr = 4 * len(registers)
        sp_incr_c = astree.mk_integer_constant(sp_incr)
        ll_sp_rhs = astree.mk_binary_op("plus", sprval, sp_incr_c)
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
        astree.add_expr_reachingdefs(ll_sp_rhs, [sprdef])
        astree.add_lval_defuses(hl_sp_lhs, spuses)
        astree.add_lval_defuses_high(hl_sp_lhs, spuseshigh)

        return (hl_instrs, ll_instrs)
