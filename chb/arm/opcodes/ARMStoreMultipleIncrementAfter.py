# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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

from typing import List, TYPE_CHECKING, Tuple

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


@armregistry.register_tag("STM", ARMOpcode)
class ARMStoreMultipleIncrementAfter(ARMOpcode):
    """Stores multiple registers to consecutive memory locations.

    STM<c> <Rn>, <registers>

    tags[1]: <c>
    args[0]: writeback
    args[1]: index of Rn in arm dictionary
    args[2]: index of registers in arm dictionary
    args[3]: index of base memory address

    xdata:
    ----------------------------------------
    vars[0]: base
    vars[1..n]: lhs memory locations where values are stored
    xprs[0]: base
    xprs[1]: updated base (may be unchanged in case of no writeback)
    xprs[2]: updated base (simplified)
    xprs[3..n+2]: values of registers being stored (simplified)
    rdefs[0]: reaching definition base register
    rdefs[1..n]: reaching definitions of registers being stored
    uses[0]: use of base register
    uses[1..n]: use of memory variables
    useshigh[0]: use-high of base register
    useshigh[1..n]: use-high of memory variables
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "StoreMultipleIncrementAfter")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2]]

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        wide = ".W" if self.args[4] == 1 else ""
        return cc + wide

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

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

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxx .

        vars[0..n]: lhs variables
        xprs[0..n]: rhs expressions
        """

        # TODO: Consider self.writeback like in the load case
        return '; '.join(
            str(lhs) + " := " + str(x) for (lhs, x) in zip(xdata.vars, xdata.xprs))

    # --------------------------------------------------------------------------
    # address = R[n];
    # for i = 0 to 14
    #   if registers<i> == '1' then
    #     MemA[address, 4] = R[i];
    #     address = address + 4;
    # if registers<15> == '1' then
    #   MemA[address, 4] = PCStoreValue();
    # if wback then
    #   R[n] = R[n] + 4 * BitCount(registers);
    # --------------------------------------------------------------------------
    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        regcount = len(xdata.reachingdefs) - 1
        baselhs = xdata.vars[0]
        memlhss = xdata.vars[1:]
        baserhs = xdata.xprs[0]
        baseresult = xdata.xprs[1]
        baseresultr = xdata.xprs[2]
        regrhss = xdata.xprs[3:3 + regcount]
        #rregrhss = xdata.xprs[3 + regcount:3 + (2 * regcount)]
        baserdef = xdata.reachingdefs[0]
        regrdefs = xdata.reachingdefs[1:]
        baseuses = xdata.defuses[0]
        memuses = xdata.defuses[1:]
        baseuseshigh = xdata.defuseshigh[0]
        memuseshigh = xdata.defuseshigh[1:]

        annotations: List[str] = [iaddr, "STMIA"]

        ll_wbackinstrs: List[AST.ASTInstruction] = []
        hl_wbackinstrs: List[AST.ASTInstruction] = []

        (baselval, _, _) = self.opargs[0].ast_lvalue(astree)
        (baserval, _, _) = self.opargs[0].ast_rvalue(astree)

        # Writeback means that the final address that is stored to is written
        # back into Rn
        if self.writeback:
            baseincr = astree.mk_integer_constant(4 * regcount)
            ll_base_rhs = astree.mk_binary_op("plus", baserval, baseincr)
            ll_base_assign = astree.mk_assign(baselval, ll_base_rhs, iaddr=iaddr)
            ll_wbackinstrs.append(ll_base_assign)

            hl_base_lhss = XU.xvariable_to_ast_lvals(baselhs, xdata, astree)
            hl_base_rhss = XU.xxpr_to_ast_exprs(baseresultr, xdata, iaddr, astree)
            if len(hl_base_lhss) != 1 or len(hl_base_rhss) != 1:
                raise UF.CHBError(
                    "StoreMultipleIncrementAfter (STMIA): error in wback assign")
            hl_base_lhs = hl_base_lhss[0]
            hl_base_rhs = hl_base_rhss[0]
            hl_base_assign = astree.mk_assign(hl_base_lhs, hl_base_rhs, iaddr=iaddr)
            hl_wbackinstrs.append(hl_base_assign)

            astree.add_instr_mapping(hl_base_assign, ll_base_assign)
            astree.add_instr_address(hl_base_assign, [iaddr])
            astree.add_expr_mapping(hl_base_rhs, ll_base_rhs)
            astree.add_lval_mapping(hl_base_lhs, baselval)
            astree.add_expr_reachingdefs(ll_base_rhs, [baserdef])
            astree.add_lval_defuses(hl_base_lhs, baseuses)
            astree.add_lval_defuses_high(hl_base_lhs, baseuseshigh)

        def default() -> Tuple[List[AST.ASTInstruction], List[AST.ASTInstruction]]:
            ll_instrs: List[AST.ASTInstruction] = []
            hl_instrs: List[AST.ASTInstruction] = []
            regsop = self.opargs[1]
            registers = regsop.registers
            base_incr = 0
            base_offset = base_incr
            for (i, r) in enumerate(registers):
                base_offset_c = astree.mk_integer_constant(base_offset)
                addr = astree.mk_binary_op("plus", baserval, base_offset_c)
                ll_lhs = astree.mk_memref_lval(addr)
                ll_rhs = astree.mk_register_variable_expr(r)
                ll_assign = astree.mk_assign(ll_lhs, ll_rhs, iaddr=iaddr)
                ll_instrs.append(ll_assign)
                lhs = memlhss[i]
                rhs = regrhss[i]
                hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
                hl_rhss = XU.xxpr_to_ast_exprs(rhs, xdata, iaddr, astree)
                if len(hl_lhss) != 1 or len(hl_rhss) != 1:
                    raise UF.CHBError(
                        "StoreMultipleIncrementAfter (STMIA): error in assigns")
                hl_lhs = hl_lhss[0]
                hl_rhs = hl_rhss[0]
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
                astree.add_lval_store(hl_lhs)

                base_offset += 4

            return (hl_instrs + hl_wbackinstrs, ll_instrs + ll_wbackinstrs)

        return default()
