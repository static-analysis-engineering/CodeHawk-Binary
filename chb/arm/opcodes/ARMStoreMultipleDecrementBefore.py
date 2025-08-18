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

from typing import cast, Dict, Iterable, List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, ARMOpcodeXData, simplify_result
from chb.arm.ARMOperand import ARMOperand

from chb.ast.AbstractSyntaxTree import nooffset
import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.bctypes.BCTyp import BCTypComp, BCTypArray
    from chb.invariants.VAssemblyVariable import VMemoryVariable
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class ARMStoreMultipleDecrementBeforeXData(ARMOpcodeXData):
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
    def regcount(self) -> int:
        return len(self._xdata.vars_r) - 1

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
        # TODO add writeback
        if self.is_ok:
            pairs = zip(self.memlhss, self.rrhss)
            assigns = "; ".join(str(v) + " := " + str(x) for (v, x) in pairs)
            return self.add_instruction_condition(assigns)
        else:
            return "Error value in STMDB"


@armregistry.register_tag("STMDB", ARMOpcode)
class ARMStoreMultipleDecrementBefore(ARMOpcode):
    """Stores multiple registers to consecutive memory locations.

    STMDB<c> <Rn>, <registers>

    tags[1]: <c>
    args[0]: writeback
    args[1]: index of Rn in arm dictionary
    args[2]: index of registers in arm dictionary
    args[3]: index of base memory address

    xdata:
    ---------------------------------------------
    rdefs[0]: reaching def base register
    rdefs[1..n]: reaching defs registers being stored
    defuse[0]: use of base regster
    defuse[1..n]: use of memory variables
    defusehigh[0]: use-hign of base register
    defusehigh[1..n]: use-high of memory variables
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "StoreMultipleDecrementBefore")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2]]

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
        xd = ARMStoreMultipleDecrementBeforeXData(xdata)
        if xd.is_ok:
            return xd.annotation
        else:
            return "Error value"

    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        baseop = self.operands[0]
        regsop = self.operands[1]
        if not regsop.is_register_list:
            raise UF.CHBError("Argument to STMDB is not a register list")

        annotations: List[str] = [iaddr, "STMDB"]

        (reglval, _, _) = baseop.ast_lvalue(astree)
        (regrval, _, _) = baseop.ast_rvalue(astree)

        instrs: List[AST.ASTInstruction] = []
        registers = regsop.registers
        reg_decr = 4 * len(registers)
        reg_offset = reg_decr
        for r in registers:
            reg_offset_c = astree.mk_integer_constant(reg_offset)
            addr = astree.mk_binary_op("minus", regrval, reg_offset_c)
            lhs = astree.mk_memref_lval(addr)
            rhs = astree.mk_register_variable_expr(r)
            instrs.append(astree.mk_assign(
                lhs,
                rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations))
            reg_offset -= 4
        if self.args[0] == 1:
            reg_decr_c = astree.mk_integer_constant(reg_decr)
            reg_rhs = astree.mk_binary_op("minus", regrval, reg_decr_c)
            instrs.append(astree.mk_assign(
                reglval,
                reg_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations))
        return instrs

    def ast(self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        vars = xdata.vars
        xprs = xdata.xprs[:-1]
        basexpr = xdata.xprs[-1]

        instrs: List[AST.ASTInstruction] = []
        annotations: List[str] = [iaddr, "STMDB"]

        rhss = XU.xxpr_list_to_ast_exprs(xprs, xdata, iaddr, astree)

        return instrs

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        '''
        regcount = len(xdata.reachingdefs) - 1
        baselhs = xdata.vars[0]
        memlhss = xdata.vars[1:]
        baserhs = xdata.xprs[0]
        baseresult = xdata.xprs[1]
        baseresultr = xdata.xprs[2]
        regrhss = xdata.xprs[3:3 + regcount]
        rregrhss = xdata.xprs[3 + regcount:3 + (2 * regcount)]
        baserdef = xdata.reachingdefs[0]
        regrdefs = xdata.reachingdefs[1:]
        baseuses = xdata.defuses[0]
        memuses = xdata.defuses[1:]
        baseuseshigh = xdata.defuseshigh[0]
        memuseshigh = xdata.defuseshigh[1:]
        '''

        xd = ARMStoreMultipleDecrementBeforeXData(xdata)

        if xd.are_cmemlhss_ok:
            memlhss = xd.cmemlhss
        elif xd.are_memlhss_ok:
            memlhss = xd.memlhss
        else:
            chklogger.logger.error(
                "STMDB: Error value encountered in LHSs at address %s", iaddr)
            return ([], [])

        if xd.are_crhss_ok:
            regrhss = xd.crhss
        elif xd.are_rrhss_ok:
            regrhss = xd.rhss
        else:
            chklogger.logger.error(
                "STMDB: Error value encountered in RHSs at address %s", iaddr)
            return ([], [])

        annotations: List[str] = [iaddr, "STMDB"]

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
        base_offset = 4 * xd.regcount
        for (i, r) in enumerate(registers):

            # low-level assignments

            base_offset_c = astree.mk_integer_constant(base_offset)
            addr = astree.mk_binary_op("minus", baserval, base_offset_c)
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

            base_offset -= 4

            if (
                    (memlhs.is_memory_variable
                     and cast("VMemoryVariable",
                              memlhs.denotation).base.is_basevar)):
                astree.add_expose_instruction(hl_assign.instrid)

        if self.writeback:

            # low-level base assignment

            basedecr = 4 * xd.regcount
            basedecr_c = astree.mk_integer_constant(basedecr)

            ll_base_lhs = baselval
            ll_base_rhs = astree.mk_binary_op("minus", baserval, basedecr_c)
            ll_base_assign = astree.mk_assign(
                ll_base_lhs,
                ll_base_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)

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

    '''
        ll_wbackinstrs: List[AST.ASTInstruction] = []
        hl_wbackinstrs: List[AST.ASTInstruction] = []

        (baselval, _, _) = self.opargs[0].ast_lvalue(astree)
        (baserval, _, _) = self.opargs[0].ast_rvalue(astree)

        if self.writeback:
            basedecr = astree.mk_integer_constant(4 * regcount)
            ll_base_rhs = astree.mk_binary_op("minus", baserval, basedecr)
            ll_base_assign = astree.mk_assign(baselval, ll_base_rhs, iaddr=iaddr)
            ll_wbackinstrs.append(ll_base_assign)

            hl_base_lhss = XU.xvariable_to_ast_lvals(baselhs, xdata, astree)
            hl_base_rhss = XU.xxpr_to_ast_exprs(baseresultr, xdata, iaddr, astree)
            if len(hl_base_lhss) != 1 or len(hl_base_rhss) != 1:
                raise UF.CHBError(
                    "StoreMultipleDecrementBefore (STMDB): error in wback assign")
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
            base_decr = 4 * regcount
            base_offset = base_decr
            for (i, r) in enumerate(registers):
                base_offset_c = astree.mk_integer_constant(base_offset)
                addr = astree.mk_binary_op("minus", baserval, base_offset_c)
                ll_lhs = astree.mk_memref_lval(addr)
                ll_rhs = astree.mk_register_variable_expr(r)
                ll_assign = astree.mk_assign(ll_lhs, ll_rhs, iaddr=iaddr)
                ll_instrs.append(ll_assign)

                lhs = memlhss[i]
                rhs = rregrhss[i]
                hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
                hl_rhss = XU.xxpr_to_ast_exprs(rhs, xdata, iaddr, astree)
                if len(hl_lhss) != 1 or len(hl_rhss) != 1:
                    raise UF.CHBError(
                        "StoreMultipleDecrementBefore (STMDB): error in assigns")
                hl_lhs = hl_lhss[0]
                hl_rhs = hl_rhss[0]
                hl_assign = astree.mk_assign(hl_lhs, hl_rhs, iaddr=iaddr)
                hl_instrs.append(hl_assign)

                astree.add_instr_mapping(hl_assign, ll_assign)
                astree.add_instr_address(hl_assign, [iaddr])
                astree.add_expr_mapping(hl_rhs, ll_rhs)
                astree.add_lval_mapping(hl_lhs, ll_lhs)
                astree.add_expr_reachingdefs(ll_rhs, [regrdefs[i]])
                astree.add_lval_defuses(hl_lhs, memuses[i])
                astree.add_lval_defuses_high(hl_lhs, memuseshigh[i])

                base_offset -= 4

            return (hl_instrs + hl_wbackinstrs, ll_instrs + ll_wbackinstrs)

        ll_instrs: List[AST.ASTInstruction] = []
        hl_instrs: List[AST.ASTInstruction] = []

        rhss = XU.xxpr_list_to_ast_exprs(rregrhss, xdata, iaddr, astree)

        if len(rhss) != 1:
            chklogger.logger.warning(
                "StoreMultipleDecrementBefore (STMDB): No or multiple values "
                + "for rhs: %s at address %s (use default)",
                ", ".join(str(r) for r in rhss),
                iaddr)
            return default()

        rhs = rhss[0]
        rhstype = rhs.ctype(astree.ctyper)
        if rhstype is None:
            chklogger.logger.warning(
                "StoreMultipleDecrementBefore (STMDB): No type found for %s "
                + "at address %s (use default)",
                str(rhs),
                iaddr)
            return default()

        if not rhstype.is_compound:
            chklogger.logger.warning(
                "StoreMultipleDecrementBefore (STMDB): Type is not a struct: "
                + "%s at address %s (use default)",
                str(rhs.ctype(astree.ctyper)),
                iaddr)
            return default()

        # Right-hand side is a struct

        rhstype = cast(AST.ASTTypComp, rhs.ctype(astree.ctyper))
        compinfo = astree.compinfo(rhstype.compkey)

        if not memlhss[0].is_memory_variable:
            chklogger.logger.warning(
                "StoreMultipleDecrementBefore (STMDB): First variable is not "
                + "a memory variable: %s at address %s (use default)",
                str(memlhss[0]),
                iaddr)
            return default()

        xvar = cast("VMemoryVariable", memlhss[0].denotation)
        if not xvar.base.is_local_stack_frame:
            chklogger.logger.warning(
                "StoreMultipleDecrementBefore (STMDB): Variable is not a "
                + "stack variable: %s at address %s (use default)",
                str(xvar),
                iaddr)
            return default()

        startingoffset = xvar.offset.offsetvalue()
        offset = startingoffset
        rhs0 = cast(AST.ASTLvalExpr, rhss[0])
        localvarassigns: Dict[int, AST.ASTAssign] = {}

        def localvarassigns_at(offset: int) -> List[AST.ASTAssign]:
            result: List[AST.ASTAssign] = []
            for (o, a) in localvarassigns.items():
                if o >= offset and o < (offset + 4):
                    result.append(a)
            return result

        for field in compinfo.fieldinfos:
            fieldtype = astree.resolve_type(field.fieldtype)

            if fieldtype.is_scalar:
                lhs = astree.mk_stack_variable_lval(offset, vtype=fieldtype)
                fieldoffset = astree.mk_field_offset(
                    field.fieldname, compinfo.compkey)
                rhslval = astree.mk_lval(rhs0.lval.lhost, fieldoffset)
                rhs = astree.mk_lval_expr(rhslval)
                fieldassign = astree.mk_assign(lhs, rhs, iaddr=iaddr)
                localvarassigns[offset] = fieldassign
                fieldsize = astree.type_size_in_bytes(fieldtype)
                if fieldsize is not None:
                    offset += fieldsize
                else:
                    chklogger.logger.warning(
                        "StoreMultipleDecrementBefore (STMDB): Size of field "
                        + "%s cannot be determined at address %s (use default)",
                        str(field),
                        iaddr)
                    return default()

            elif fieldtype.is_array:
                arraytype = cast(AST.ASTTypArray, fieldtype)
                if not arraytype.has_constant_size():
                    chklogger.logger.warning(
                        "StoreMultipleDecrementBefore (STMDB): Array type "
                        + "does not have constant size at address %s",
                        iaddr)
                    return default()

                arraysize = arraytype.size_value()

                elttype = astree.resolve_type(arraytype.tgttyp)
                eltsize = astree.type_size_in_bytes(elttype)
                if eltsize is None:
                    chklogger.logger.warning(
                        "StoreMultipleDecrementBefore (STMDB): Array element "
                        + "size of field %s not known at address %s",
                        str(field),
                        iaddr)
                    return default()

                for index in range(0, arraysize):
                    lhs = astree.mk_stack_variable_lval(offset, vtype=elttype)
                    indexoffset = astree.mk_scalar_index_offset(index)
                    varoffset = astree.mk_field_offset(
                        field.fieldname, compinfo.compkey, offset=indexoffset)
                    rhslval = astree.mk_lval(rhs0.lval.lhost, varoffset)
                    rhs = astree.mk_lval_expr(rhslval)
                    eltassign = astree.mk_assign(lhs, rhs, iaddr=iaddr)
                    localvarassigns[offset] = eltassign
                    offset += eltsize
            else:
                fieldsize = astree.type_size_in_bytes(fieldtype)
                if fieldsize is None:
                    chklogger.logger.warning(
                        "StoreMultipleDecrementBefore (STMDB): Field size not "
                        + "known for field %s at address %s",
                        str(field),
                        iaddr)
                    return default()

                lhs = astree.mk_stack_variable_lval(offset, vtype=fieldtype)
                fieldoffset = astree.mk_field_offset(
                    field.fieldname, compinfo.compkey)
                rhslval = astree.mk_lval(rhs0.lval.lhost, fieldoffset)
                rhs = astree.mk_lval_expr(rhslval)
                fieldassign = astree.mk_assign(lhs, rhs, iaddr=iaddr)
                localvarassigns[offset] = fieldassign

                offset += fieldsize

        ll_instructions: List[AST.ASTInstruction] = []
        hl_instructions: List[AST.ASTInstruction] = []

        regsop = self.opargs[1]
        registers = regsop.registers
        base_offset = startingoffset + (4 * regcount)
        for (i, r) in enumerate(registers):
            ll_offset = 4 * (4 - i)
            realoffset = base_offset - ll_offset
            hl_assigns = localvarassigns_at(realoffset)
            ll_offset_c = astree.mk_integer_constant(ll_offset)
            addr = astree.mk_binary_op("minus", baserval, ll_offset_c)
            ll_lhs = astree.mk_memref_lval(addr)
            ll_rhs = astree.mk_register_variable_expr(r)
            ll_assign = astree.mk_assign(ll_lhs, ll_rhs, iaddr=iaddr)

            ll_instructions.append(ll_assign)
            hl_instructions.extend(hl_assigns)

            for hl_asg in hl_assigns:
                astree.add_local_vardefinition(
                    iaddr, str(hl_asg.lhs), hl_asg.rhs)
                astree.add_instr_mapping(hl_asg, ll_assign)
                astree.add_instr_address(hl_asg, [iaddr])
                astree.add_expr_mapping(hl_asg.rhs, ll_assign.rhs)
                astree.add_lval_mapping(hl_asg.lhs, ll_assign.lhs)
                astree.add_lval_defuses(hl_asg.lhs, memuses[i])
                astree.add_lval_defuses_high(hl_asg.lhs, memuseshigh[i])

            astree.add_expr_reachingdefs(ll_assign.rhs, [regrdefs[i]])

        return (
            hl_instructions + hl_wbackinstrs,
            ll_instructions + ll_wbackinstrs)
    '''
