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

from typing import cast, List, TYPE_CHECKING, Tuple

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
    from chb.invariants.VAssemblyVariable import VRegisterVariable
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr, XprConstant, XprVariable


class ARMStoreMultipleIncrementAfterXData(ARMOpcodeXData):

    def __init__(self, xdata: InstrXData) -> None:
        ARMOpcodeXData.__init__(self, xdata)

    @property
    def is_ldmstm_aggregate(self) -> bool:
        return "agg-ldmstm" in self.xdata.tags

    def ldmstm_xpr(self, index: int, msg: str) -> "XXpr":
        if self.is_ldmstm_aggregate:
            return self.xpr(index, msg)
        else:
            raise UF.CHBError("Not an ldmstm aggregate: " + msg)

    @property
    def xdst(self) -> "XXpr":
        return self.ldmstm_xpr(0, "xdst")

    @property
    def is_xdst_unknown(self) -> bool:
        return self.xdata.xprs_r[0] is None

    @property
    def xsrc(self) -> "XXpr":
        return self.ldmstm_xpr(1, "xsrc")

    @property
    def is_xsrc_unknowns(self) -> bool:
        return self.xdata.xprs_r[1] is None

    @property
    def xxdst(self) -> "XXpr":
        return self.ldmstm_xpr(2, "xxdst")

    @property
    def is_xxdst_unknown(self) -> bool:
        return self.xdata.xprs_r[2] is None

    @property
    def xxsrc(self) -> "XXpr":
        return self.ldmstm_xpr(3, "xxsrc")

    @property
    def is_xxsrc_unknown(self) -> bool:
        return self.xdata.xprs_r[3] is None

    @property
    def copysize(self) -> int:
        if self.is_ldmstm_aggregate:
            return self.xdata.ints[0]
        else:
            raise UF.CHBError("Not an ldmstm aggregate")

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
        return [self.var(i, "memlhs-" + str(i)) for i in range(1, self.regcount + 1)]

    @property
    def rhss(self) -> List["XXpr"]:
        return [self.xpr(i, "rhs-" + str(i)) for i in range(3, self.regcount + 3)]

    @property
    def annotation(self) -> str:
        if self.is_ok:
            if self.is_ldmstm_aggregate:
                return (
                    "memcpy(" +
                    str(self.xxdst)
                    + ", "
                    + str(self.xxsrc)
                    + ", "
                    + str(self.copysize)
                    + ")")
            else:
                assigns = []
                for (memlhs, rhs) in zip(self.memlhss, self.rhss):
                    assigns.append(str(memlhs) + " := " + str(rhs))
                return "; ".join(assigns)
        else:
            if self.is_ldmstm_aggregate:
                if self.is_xxdst_unknown and self.is_xxsrc_unknown:
                    dst = str(self.xdst)
                    src = str(self.xsrc)
                elif self.is_xxdst_unknown:
                    dst = str(self.xdst)
                    src = str(self.xxsrc)
                else:
                    dst = str(self.xxdst)
                    src = str(self.xsrc)
                return (
                        "memcpy("
                        + dst
                        + ", "
                        + src
                        + ", "
                        + str(self.copysize)
                        + ")")
            else:
                return "not yet supported"



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

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
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
        xd = ARMStoreMultipleIncrementAfterXData(xdata)
        return xd.annotation

    def ast_prov_ldmstmcopy(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "STMIA:LDMSTMCOPY"]

        # low-level assignments

        ll_instrs: List[AST.ASTInstruction] = []
        hl_instrs: List[AST.ASTInstruction] = []

        (baselval, _, _) = self.opargs[0].ast_lvalue(astree)
        (baserval, _, _) = self.opargs[0].ast_rvalue(astree)

        regsop = self.opargs[1]
        registers = regsop.registers
        regcount = len(registers)
        base_offset = 0
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

            base_offset += 4

        if self.writeback:

            # low-level base assignment

            baseincr = 4 * regcount
            baseincr_c = astree.mk_integer_constant(baseincr)

            ll_base_lhs = baselval
            ll_base_rhs = astree.mk_binary_op("plus", baserval, baseincr_c)
            ll_base_assign = astree.mk_assign(
                ll_base_lhs,
                ll_base_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            ll_instrs.append(ll_base_assign)

        # high-level call

        xd = ARMStoreMultipleIncrementAfterXData(xdata)
        if not xd.is_ok:
            if xd.is_xxsrc_unknown and xd.is_xxdst_unknown:
                chklogger.logger.error(
                    "LDM-STM-memcpy: (%s): src and dst unknown", iaddr)
            elif xd.is_xxsrc_unknown:
                chklogger.logger.error("LDM-STM-memcpy: (%s): src unknown", iaddr)
            else:
                chklogger.logger.error("LDM-STM-memcpy: (%s): dst unknown", iaddr)
            return ([], [])

        xdst = xd.xdst
        xsrc = xd.xsrc
        xxdst = xd.xxdst
        xxsrc = xd.xxsrc
        xsize = xd.copysize

        # low-level arguments

        xdst = cast("XprVariable", xdst)
        xdstvar = cast("VRegisterVariable", xdst.variable.denotation)
        xdstreg = xdstvar.register
        ll_dstlval = astree.mk_register_variable_lval(str(xdstreg))
        ll_dst_arg = astree.mk_lval_expression(ll_dstlval)

        xsrc = cast("XprVariable", xsrc)
        xsrcvar = cast("VRegisterVariable", xsrc.variable.denotation)
        xsrcreg = xsrcvar.register
        ll_srclval = astree.mk_register_variable_lval(str(xsrcreg))
        ll_src_arg = astree.mk_lval_expression(ll_srclval)

        # high-level arguments

        if xxdst.is_stack_address:
            offset = xxdst.stack_address_offset()
            stackvar = astree.mk_stack_variable_lval(offset)
            stackvartyp = stackvar.ctype(astree.ctyper)
            if stackvartyp is not None and stackvartyp.is_array:
                hl_dst_arg = astree.mk_lval_expr(stackvar)
            else:
                hl_dst_arg = astree.mk_address_of(stackvar)

        else:
            hl_dst_arg = XU.xxpr_to_ast_def_expr(xxdst, xdata, iaddr, astree)

        if xxsrc.is_string_reference:
            cstr = xxsrc.constant.string_reference()
            saddr = hex(xxsrc.constant.value)
            hl_src_arg: AST.ASTExpr = astree.mk_string_constant(
                ll_src_arg, cstr, saddr)

        elif xxsrc.is_global_address:
            hexgaddr = hex(xxsrc.constant.value)
            if hexgaddr in astree.global_addresses:
                vinfo = astree.global_addresses[hexgaddr]
                vtype = vinfo.vtype
                if vtype is not None:
                    if vtype.is_array:
                        hl_src_arg = astree.mk_vinfo_lval_expression(vinfo)
                    else:
                        hl_src_arg = astree.mk_address_of(
                            astree.mk_vinfo_lval(vinfo))
                else:
                    chklogger.logger.warning(
                        ("Type of global address %s at instr.address %s "
                         + "not known"),
                        str(xxsrc), iaddr)
                    hl_src_arg = astree.mk_address_of(
                        astree.mk_vinfo_lval(vinfo))
            else:
                chklogger.logger.error(
                    "Unknown global address %s as call argument at %s",
                    hexgaddr, iaddr)
                hl_src_arg = astree.mk_temp_lval_expression()

        elif xxsrc.is_stack_address:
            negoffset = xxsrc.stack_address_offset()
            offset = -negoffset
            stackvar = astree.mk_stack_variable_lval(offset)
            hl_src_arg = astree.mk_lval_expr(stackvar)

        else:
            hl_src_arg = XU.xxpr_to_ast_def_expr(xxsrc, xdata, iaddr, astree)

        if xxsrc.is_string_reference:
            # TODO: add check for string length vs size
            hl_tgt = astree.mk_global_variable_expr("strcpy")
            hl_args = [hl_dst_arg, hl_src_arg]

        else:
            hl_tgt = astree.mk_global_variable_expr("memcpy")
            hl_size_arg = astree.mk_integer_constant(xsize)
            hl_args = [hl_dst_arg, hl_src_arg, hl_size_arg]

        hl_call = cast(AST.ASTInstruction, astree.mk_call(
            None,
            hl_tgt,
            hl_args,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations))

        astree.add_instr_mapping(hl_call, ll_instrs[0])
        astree.add_instr_address(hl_call, [iaddr] + xdata.subsumes())

        return ([hl_call], ll_instrs)

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

        if xdata.instruction_subsumes():
            return self.ast_prov_ldmstmcopy(astree, iaddr, bytestring, xdata)

        else:
            chklogger.logger.error(
                "AST conversion of STM not yet supported at address %s",
                iaddr)
            return ([], [])

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

        # low-level assignments

        ll_instrs: List[AST.ASTInstruction] = []
        hl_instrs: List[AST.ASTInstruction] = []

        (baselval, _, _) = self.opargs[0].ast_lvalue(astree)
        (baserval, _, _) = self.opargs[0].ast_rvalue(astree)

        regsop = self.opargs[1]
        registers = regsop.registers
        base_offset = 0
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
            astree.add_expr_reachingdefs(ll_rhs, [regrdefs[i]])
            astree.add_lval_defuses(hl_lhs, memuses[i])
            astree.add_lval_defuses_high(hl_lhs, memuseshigh[i])

            base_offset += 4

        if self.writeback:

            # low-level base assignment

            baseincr = 4 * regcount
            baseincr_c = astree.mk_integer_constant(baseincr)

            ll_base_lhs = baselval
            ll_base_rhs = astree.mk_binary_op("plus", baserval, baseincr_c)
            ll_base_assign = astree.mk_assign(
                ll_base_lhs,
                ll_base_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            ll_instrs.append(ll_base_assign)

            # high-level base assignment

            hl_base_lhs = XU.xvariable_to_ast_lval(baselhs, xdata, iaddr, astree)
            hl_base_rhs = XU.xxpr_to_ast_def_expr(
                baseresultr, xdata, iaddr, astree)
            hl_base_assign = astree.mk_assign(
                hl_base_lhs,
                hl_base_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)
            hl_instrs.append(hl_base_assign)

            astree.add_instr_mapping(hl_base_assign, ll_base_assign)
            astree.add_instr_address(hl_base_assign, [iaddr])
            astree.add_expr_mapping(hl_base_rhs, ll_base_rhs)
            astree.add_lval_mapping(hl_base_lhs, ll_base_lhs)
            astree.add_expr_reachingdefs(ll_base_rhs, [baserdef])
            astree.add_lval_defuses(hl_base_lhs, baseuses)
            astree.add_lval_defuses_high(hl_base_lhs, baseuseshigh)

        return (hl_instrs, ll_instrs)
