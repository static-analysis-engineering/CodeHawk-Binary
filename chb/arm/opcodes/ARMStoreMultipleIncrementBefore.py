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
    from chb.invariants.VAssemblyVariable import VMemoryVariable
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMStoreMultipleIncrementBeforeXData(ARMOpcodeXData):

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def regcount(self) -> int:
        return len(self.xdata.vars_r) - 1

    @property
    def baselhs(self) -> "XVariable":
        return self.var(0, "baselhs")

    @property
    def is_baselhs_known(self) -> bool:
        return self.xdata.vars_r[0] is not None

    @property
    def memlhss(self) -> List["XVariable"]:
        return [self.var(i, "memlhs-" + str(i))
                for i in range(1, self.regcount + 1)]

    @property
    def rhss(self) -> List["XXpr"]:
        return [self.xpr(i, "rhs-" + str(i))
                for i in range(3, self.regcount + 3)]

    @property
    def annotation(self) -> str:
        wbu = self.writeback_update()
        if self.is_ok:
            assigns: List[str] = []
            for (memlhs, rhs) in zip(self.memlhss, self.rhss):
                assigns.append(str(memlhs) + " := " + str(rhs))
            return ": ".join(assigns) + wbu
        else:
            return "Error value"



@armregistry.register_tag("STMIB", ARMOpcode)
class ARMStoreMultipleIncrementBefore(ARMOpcode):
    """Stores multiple registers to consecutive memory locations.

    STMIB<c> <Rn>, <registers>

    tags[1]: <c>
    args[0]: writeback
    args[1]: index of Rn in arm dictionary
    args[2]: index of registers in arm dictionary
    args[3]: index of base memory address
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "StoreMultipleIncrementBefore")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        xd = ARMStoreMultipleIncrementBeforeXData(xdata)
        return xd.annotation

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        xd = ARMStoreMultipleIncrementBeforeXData(xdata)
        if not xd.is_ok:
            chklogger.logger.error(
                "STMIB: Error value encountered at address %s", iaddr)
            return ([], [])

        annotations: List[str] = [iaddr, "STMIB"]

        ll_instrs: List[AST.ASTInstruction] = []
        hl_instrs: List[AST.ASTInstruction] = []

        (baselval, _, _) = self.opargs[0].ast_lvalue(astree)
        (baserval, _, _) = self.opargs[0].ast_rvalue(astree)

        memlhss = xd.memlhss
        regrhss = xd.rhss
        regrdefs = xdata.reachingdefs[1:]
        memuses = xdata.defuses[1:]
        memuseshigh = xdata.defuseshigh[1:]

        regsop = self.opargs[1]
        registers = regsop.registers
        base_offset = 4
        for (i, r) in enumerate(registers):

            # low-level assignments

            base_offset_c = astree.mk_integer_constant(base_offset)
            addr = astree.mk_binary_op("plus", baserval, base_offset_c)
            ll_lhs = astree.mk_memref_lval(addr)
            ll_rhs = astree.mk_register_variable_expr(r)
            ll_assign = astree.mk_assign(
                ll_lhs,
                ll_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            ll_instrs.append(ll_assign)

            # high-level assignments

            memlhs = memlhss[i]
            regrhs = regrhss[i]

            hl_lhs = XU.xvariable_to_ast_lval(memlhs, xdata, iaddr, astree)
            hl_rhs = XU.xxpr_to_ast_def_expr(regrhs, xdata, iaddr, astree)
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
            astree.add_expr_reachingdefs(ll_rhs, [regrdefs[i]])
            astree.add_lval_defuses(hl_lhs, memuses[i])
            astree.add_lval_defuses_high(hl_lhs, memuseshigh[i])

            base_offset += 4

            if (
                    (memlhs.is_memory_variable
                     and cast("VMemoryVariable", memlhs.denotation).base.is_basevar)):
                astree.add_expose_instruction(hl_assign.instrid)

        # TODO: add writeback update

        return (hl_instrs, ll_instrs)
