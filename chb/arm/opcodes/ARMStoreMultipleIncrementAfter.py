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

from typing import cast, Iterable, List, TYPE_CHECKING, Tuple

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
    from chb.invariants.VAssemblyVariable import (
        VRegisterVariable, VMemoryVariable)
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr, XprConstant, XprVariable


class ARMStoreMultipleIncrementAfterXData(ARMOpcodeXData):
    """Data format:
    - variables:
    0: baselhs
    1..n: memlhss

    - c variables:
    1..n: cmemlhss

    - expressions:
    0: baserhs
    1..n: rhss
    n+1..2n: rrhss
    2n+1..3n: xaddrs

    - c expressions:
    0..n-1: crhss
    n..2n-1: cxaddrs
    """

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
    def is_xdst_ok(self) -> bool:
        return self.is_xpr_ok(0)

    @property
    def xsrc(self) -> "XXpr":
        return self.ldmstm_xpr(1, "xsrc")

    @property
    def is_xsrc_ok(self) -> bool:
        return self.is_xpr_ok(1)

    @property
    def xxdst(self) -> "XXpr":
        return self.ldmstm_xpr(2, "xxdst")

    @property
    def is_xxdst_ok(self) -> bool:
        return self.is_xpr_ok(2)

    @property
    def xxsrc(self) -> "XXpr":
        return self.ldmstm_xpr(3, "xxsrc")

    @property
    def is_xxsrc_ok(self) -> bool:
        return self.is_xpr_ok(3)

    @property
    def cdst(self) -> "XXpr":
        return self.cxpr(0, "cdst")

    @property
    def is_cdst_ok(self) -> bool:
        return self.is_cxpr_ok(0)

    @property
    def csrc(self) -> "XXpr":
        return self.cxpr(1, "csrc")

    @property
    def is_csrc_ok(self) -> bool:
        return self.is_cxpr_ok(1)

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
    def memlhs_range(self) -> Iterable[int]:
        return range(1, self.regcount + 1)

    @property
    def memlhss(self) -> List["XVariable"]:
        return [self.var(i, "memlhs") for i in self.memlhs_range]

    @property
    def are_memlhss_ok(self) -> bool:
        return all(self.is_var_ok(i) for i in self.memlhs_range)

    @property
    def cmemlhs_range(self) -> Iterable[int]:
        return range(0, self.regcount)

    @property
    def cmemlhss(self) -> List["XVariable"]:
        return [self.cvar(i, "cmemlhs") for i in self.cmemlhs_range]

    @property
    def are_cmemlhss_ok(self) -> bool:
        return all(self.is_cvar_ok(i) for i in self.cmemlhs_range)

    @property
    def baserhs(self) -> "XXpr":
        return self.xpr(0, "baserhs")

    @property
    def rhs_range(self) -> Iterable[int]:
        return range(1, self.regcount + 1)

    @property
    def rhss(self) -> List["XXpr"]:
        return [self.xpr(i, "rhs") for i in self.rhs_range]

    @property
    def are_rhss_ok(self) -> bool:
        return all(self.is_xpr_ok(i) for i in self.rhs_range)

    @property
    def rrhs_range(self) -> Iterable[int]:
        return range(self.regcount + 1, (2 * self.regcount) + 1)

    @property
    def rrhss(self) -> List["XXpr"]:
        return [self.xpr(i, "rrhs") for i in self.rrhs_range]

    @property
    def are_rrhss_ok(self) -> bool:
        return all(self.is_xpr_ok(i) for i in self.rrhs_range)

    @property
    def crhs_range(self) -> Iterable[int]:
        return range(0, self.regcount)

    @property
    def crhss(self) -> List["XXpr"]:
        return [self.cxpr(i, "crhs") for i in self.crhs_range]

    @property
    def are_crhss_ok(self) -> bool:
        return all(self.is_cxpr_ok(i) for i in self.crhs_range)

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
                if self.is_xxdst_ok:
                    dst = str(self.xxdst)
                elif self.is_xdst_ok:
                    dst = str(self.xdst)
                else:
                    dst = "dst:error value"
                if self.is_xxsrc_ok:
                    src = str(self.xxsrc)
                elif self.is_xsrc_ok:
                    src = str(self.xsrc)
                else:
                    src = "src:error value"
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

        xdst = xd.xdst
        xsrc = xd.xsrc
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

        if xd.is_xxdst_ok:
            xxdst = xd.xxdst
        else:
            xxdst = xdst

        if xd.is_xxsrc_ok:
            xxsrc = xd.xxsrc
        else:
            xxsrc = xsrc

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

        xd = ARMStoreMultipleIncrementAfterXData(xdata)

        if xd.are_cmemlhss_ok:
            memlhss = xd.cmemlhss
        elif xd.are_memlhss_ok:
            memlhss = xd.memlhss
        else:
            chklogger.logger.error(
                "STM: Error value encountered in LHSs at address %s", iaddr)
            return ([], [])

        if xd.are_crhss_ok:
            regrhss = xd.crhss
        elif xd.are_rrhss_ok:
            regrhss = xd.rhss
        else:
            chklogger.logger.error(
                "STM: Error value encountered in RHSs at address %s", iaddr)
            return ([], [])

        annotations: List[str] = [iaddr, "STM"]

        baselhs = xd.baselhs
        baserhs = xd.baserhs
        baserdef = xdata.reachingdefs[0]
        baseuses = xdata.defuses[0]
        baseuseshigh = xdata.defuseshigh[0]

        # low-level assignments

        ll_instrs: List[AST.ASTInstruction] = []
        hl_instrs: List[AST.ASTInstruction] = []

        (baselval, _, _) = self.opargs[0].ast_lvalue(astree)
        (baserval, _, _) = self.opargs[0].ast_rvalue(astree)

        regrdefs = xdata.reachingdefs[1:]
        memuses = xdata.defuses[1:]
        memuseshigh = xdata.defuseshigh[1:]

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
                     and cast("VMemoryVariable",
                              memlhs.denotation).base.is_basevar)):
                astree.add_expose_instruction(hl_assign.instrid)

        if self.writeback:

            # low-level base assignment

            baseincr = 4 * xd.regcount
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

            baseresult = xd.get_base_update_xpr()
            hl_base_lhs = XU.xvariable_to_ast_lval(baselhs, xdata, iaddr, astree)
            hl_base_rhs = XU.xxpr_to_ast_def_expr(
                baseresult, xdata, iaddr, astree)
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
