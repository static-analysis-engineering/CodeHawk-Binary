# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023 Aarno Labs LLC
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
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("LDM", ARMOpcode)
class ARMLoadMultipleIncrementAfter(ARMOpcode):
    """Loads multiple registers from consecutive memory locations.

    LDM<c> <Rn>, <registers>

    tags[1]: <c>
    args[0]: writeback
    args[1]: index of Rn in arm dictionary
    args[2]: index of registers in arm dictionary
    args[3]: index of base memory address

    xdata format: vv[n]xxxx[n]rr[n]dd[n]hh[n]
    ----------------------------------------
    vars[0]: base lhs
    vars[1..n]: register lhss
    xprs[0]: base rhs
    xprs[1]: updated base (may be unchanged in case of no writeback)
    xprs[2]: updated base (simplified)
    xprs[3..n+2]: values of memory locations read
    rdefs[0]: reaching definition base register
    rdefs[1..n]: reaching definition memory locations
    uses[0]: base lhs
    uses[1..n]: register lhss
    useshigh[0]: base lhs
    useshigh[1..n]: register lhss
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "LoadMultipleIncrementAfter")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:]]

    @property
    def operandstring(self) -> str:
        return (
            str(self.armd.arm_operand(self.args[1]))
            + ("!" if self.args[0] == 1 else "")
            + ", "
            + str(self.armd.arm_operand(self.args[2])))

    @property
    def writeback(self) -> bool:
        return self.args[0] == 1

    def is_load_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        wb = ""
        if self.writeback:
            wb = "; " + str(xdata.vars[0]) + " := " + str(xdata.xprs[2])
        return (
            "; ".join(str(v)
                      + " := "
                      + str(x) for (v, x) in zip(xdata.vars[1:], xdata.xprs[3:]))
            + wb)

    # -------------------------------------------------------------------------
    # address = R[n];
    # for i = 0 to 14
    #   if registers<i> == '1' then
    #     R[i] = MemA[address, 4];
    #     address = address + 4;
    # if registers<15> == '1' then
    #   loadWritePC(MemA[address, 4]);
    # if wback && registers<n> == '0' then
    #   R[n] = R[n] + 4 * BitCount(registers);
    # -------------------------------------------------------------------------
    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        regcount = len(xdata.reachingdefs) - 1
        baselhs = xdata.vars[0]
        reglhss = xdata.vars[1:]
        baserhs = xdata.xprs[0]
        baseresult = xdata.xprs[1]
        baseresultr = xdata.xprs[2]
        memrhss = xdata.xprs[3:3 + regcount]
        baserdef = xdata.reachingdefs[0]
        memrdefs = xdata.reachingdefs[1:]
        baseuses = xdata.defuses[0]
        reguses = xdata.defuses[1:]
        baseuseshigh = xdata.defuseshigh[0]
        reguseshigh = xdata.defuseshigh[1:]

        annotations: List[AST.ASTInstruction] = []

        ll_wbackinstrs: List[AST.ASTInstruction] = []
        hl_wbackinstrs: List[AST.ASTInstruction] = []

        (baselval, _, _) = self.opargs[0].ast_lvalue(astree)
        (baserval, _, _) = self.opargs[0].ast_rvalue(astree)

        if self.writeback:
            baseincr = astree.mk_integer_constant(4 * regcount)
            ll_base_rhs = astree.mk_binary_op("plus", baserval, baseincr)
            ll_base_assign = astree.mk_assign(baselval, ll_base_rhs, iaddr=iaddr)
            ll_wbackinstrs.append(ll_base_assign)

            hl_base_lhss = XU.xvariable_to_ast_lvals(baselhs, xdata, astree)
            hl_base_rhss = XU.xxpr_to_ast_exprs(baseresultr, xdata, iaddr, astree)
            if len(hl_base_lhss) != 1 or len(hl_base_rhss) != 1:
                raise UF.CHBError(
                    "LoadMultiple (LDM): error in wback assign")
            hl_base_lhs = hl_base_lhss[0]
            hl_base_rhs = hl_base_rhss[0]
            hl_base_assign = astree.mk_assign(hl_base_lhs, hl_base_rhs, iaddr=iaddr)
            hl_wbackinstrs.append(hl_base_assign)

        def default() -> Tuple[List[AST.ASTInstruction], List[AST.ASTInstruction]]:
            ll_instrs: List[AST.ASTInstruction] = []
            hl_instrs: List[AST.ASTInstruction] = []
            regsop = self.opargs[1]
            registers = regsop.registers
            base_increm = 0
            base_offset = base_increm
            for (i, r) in enumerate(registers):
                base_offset_c = astree.mk_integer_constant(base_offset)
                addr = astree.mk_binary_op("plus", baserval, base_offset_c)
                ll_lhs = astree.mk_register_variable_lval(r)
                ll_rhs = astree.mk_memref_expr(addr)
                ll_assign = astree.mk_assign(ll_lhs, ll_rhs, iaddr=iaddr)
                ll_instrs.append(ll_assign)

                lhs = reglhss[i]
                rhs = memrhss[i]
                hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
                hl_rhss = XU.xxpr_to_ast_exprs(rhs, xdata, iaddr, astree)
                if len(hl_lhss) != 1 or len(hl_rhss) != 1:
                    raise UF.CHBError(
                        "LoadMultiple (LDM): error in register-memory assigns")
                hl_lhs = hl_lhss[0]
                hl_rhs = hl_rhss[0]
                hl_assign = astree.mk_assign(hl_lhs, hl_rhs, iaddr=iaddr)
                hl_instrs.append(hl_assign)

                astree.add_instr_mapping(hl_assign, ll_assign)
                astree.add_instr_address(hl_assign, [iaddr])
                astree.add_expr_mapping(hl_rhs, ll_rhs)
                astree.add_lval_mapping(hl_lhs, ll_lhs)
                astree.add_expr_reachingdefs(ll_rhs, [memrdefs[i]])
                astree.add_lval_defuses(hl_lhs, reguses[i])
                astree.add_lval_defuses_high(hl_lhs, reguseshigh[i])

                base_offset += 4

            return (hl_instrs + hl_wbackinstrs, ll_instrs + ll_wbackinstrs)

        return default()
