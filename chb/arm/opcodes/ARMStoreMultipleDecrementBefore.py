# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs LLC
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

from typing import cast, Dict, List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

from chb.ast.AbstractSyntaxTree import nooffset
import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.bctypes.BCTyp import BCTypComp, BCTypArray
    from chb.invariants.VAssemblyVariable import VMemoryVariable


@armregistry.register_tag("STMDB", ARMOpcode)
class ARMStoreMultipleDecrementBefore(ARMOpcode):
    """Stores multiple registers to consecutive memory locations.

    STMDB<c> <Rn>, <registers>

    tags[1]: <c>
    args[0]: writeback
    args[1]: index of Rn in arm dictionary
    args[2]: index of registers in arm dictionary
    args[3]: index of base memory address

    xdata format:vv[n]xxxx[2n]r[n+1]d[n+1][h[n+1]
    ---------------------------------------------
    vars[0]: base
    vars[1..n]: lhs memory locations where values are stored
    xprs[0]: base
    xprs[1]: updated base (may be unchanged in case of no writeback)
    xprs[2]: updated base (simplified)
    xprs[3..n+2]: values of the registers being stored
    xprs[n+3..2n+2]: values of the registers being stored (simplified)
    rdefs[0]: reaching def base register
    rdefs[1..n]: reaching defs registers being stored
    defuse[0]: use of base regster
    defuse[1..n]: use of memory variables
    defusehigh[0]: use-hign of base register
    defusehigh[1..n]: use-high of memory variables
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "StoreMultipleDecrementBefore")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]

    @property
    def writeback(self) -> bool:
        return self.args[0] == 1

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        # regcount = len(xdata.vars) - 1
        regcount = len(xdata.reachingdefs) - 1

        wb = ""
        if self.writeback:
            wb = "; " + str(xdata.vars[0]) + " := " + str(xdata.xprs[2])
        return (
            "; ".join(
                str(v)
                + " := "
                + str(x) for (v, x) in
                zip(xdata.vars[1:], xdata.xprs[regcount+3:(2 * regcount)+3]))
            + wb)

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

        rhss = XU.xxpr_list_to_ast_exprs(xprs, xdata, astree)

        '''
        if len(rhss) == 1 and rhss[0].ctype and rhss[0].ctype.is_struct:
            # the registers represent a single struct
            structtype = cast("BCTypComp", rhss[0].ctype)
            compinfo = structtype.compinfo

            if vars[0].is_memory_variable:
                xvar = cast("VMemoryVariable", vars[0].denotation)
                if xvar.base.is_local_stack_frame:
                    startingoffset = xvar.offset.offsetvalue()
                    offset = startingoffset
                    for field in compinfo.fieldinfos:
                        fieldtype = field.fieldtype
                        if fieldtype.is_scalar:
                            lhs = astree.mk_stack_variable_lval(
                                offset, vtype=fieldtype)
                            fieldoffset = astree.mk_field_offset(field.fieldname, fieldtype)
                            rhslval = astree.mk_lval(rhs0.lval.lhost, fieldoffset)
                            rhs0 = cast(AST.ASTLvalExpr, rhss[0])
                            rhs = astree.mk_lval_expr(rhslval)
                            instrs.append(astree.mk_assign(lhs, rhs, annotations=annotations))
                            offset += fieldtype.byte_size()
                        elif fieldtype.is_array:
                            arraytype = cast("BCTypArray", fieldtype)
                            if arraytype.has_constant_size:
                                arraysize = arraytype.sizevalue
                                eltsize = arraytype.tgttyp.byte_size()
                                for index in range(0, arraysize):
                                    lhs = astree.mk_stack_variable_lval(
                                        offset, vtype=arraytype.tgttyp)
                                    indexoffset = astree.mk_scalar_index_offset(index)
                                    varoffset = astree.mk_field_offset(
                                        field.fieldname, fieldtype, offset=indexoffset)
                                    rhs0 = cast(AST.ASTLvalExpr, rhss[0])
                                    rhslval = astree.mk_lval(rhs0.lval.lhost, varoffset)
                                    rhs = astree.mk_lval_expr(rhslval)
                                    instrs.append(astree.mk_assign(lhs, rhs, annotations=annotations))
                                    offset += eltsize
                        else:
                            continue

            else:
                instrs.append(astree.mk_assign(lhs, rhss[0], annotations=annotations))
        else:
            for (v, x) in zip(vars, xprs):
                lhss = XU.xvariable_to_ast_lvals(v, astree)
                rhss = XU.xxpr_to_ast_exprs(x, astree)
                if len(lhss) == 1 and len(rhss) == 1:
                    lhs = lhss[0]
                    rhs = rhss[0]
                    instrs.append(astree.mk_assign(lhs, rhs, annotations=annotations))
                else:
                    raise UF.CHBError(
                        "ARMStoreMultipleDecrementBefore: multiple expressions/lvals in ast")
        '''

        return instrs

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
        rregrhss = xdata.xprs[3 + regcount:3 + (2 * regcount)]
        baserdef = xdata.reachingdefs[0]
        regrdefs = xdata.reachingdefs[1:]
        baseuses = xdata.defuses[0]
        memuses = xdata.defuses[1:]
        baseuseshigh = xdata.defuseshigh[0]
        memuseshigh = xdata.defuseshigh[1:]

        annotations: List[str] = [iaddr, "STMDB"]

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
            hl_base_rhss = XU.xxpr_to_ast_exprs(baseresultr, xdata, astree)
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
                hl_rhss = XU.xxpr_to_ast_exprs(rhs, xdata, astree)
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

        rhss = XU.xxpr_list_to_ast_exprs(rregrhss, xdata, astree)

        if len(rhss) != 1:
            astree.add_diagnostic(
                "StoreMultipleDecrementBefore (STMDB): "
                + "none or multiple values for rhs: "
                + ", ".join(str(r) for r in rhss)
                + " (use default)")
            return default()

        rhs = rhss[0]
        rhstype = rhs.ctype(astree.ctyper)
        if rhstype is None:
            astree.add_diagnostic(
                "StoreMultipleDecrementBefore (STMDB): "
                + "no type found for "
                + str(rhs)
                + " (use default)")
            return default()

        if not rhstype.is_compound:
            astree.add_diagnostic(
                "StoreMultipleDecrementBefore (STMDB): "
                + "type is not a struct: "
                + str(rhs.ctype(astree.ctyper))
                + " use default")
            return default()

        rhstype = cast(AST.ASTTypComp, rhs.ctype(astree.ctyper))
        compinfo = astree.compinfo(rhstype.compkey)

        if not memlhss[0].is_memory_variable:
            astree.add_diagnostic(
                "StoreMultipleDecrementBefore (STMDB): "
                + "first variable is not a memory var: " + str(memlhss[0]))
            return default()

        xvar = cast("VMemoryVariable", memlhss[0].denotation)
        if not xvar.base.is_local_stack_frame:
            astree.add_diagnostic(
                "StoreMultipleDecrementBefore (STMDB): "
                "variable is not a stack variable: "
                + str(xvar))
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
                offset += astree.type_size_in_bytes(fieldtype)

            elif fieldtype.is_array:
                arraytype = cast(AST.ASTTypArray, fieldtype)
                if not arraytype.has_constant_size():
                    astree.add_diagnostic(
                        "StoreMultipleDecrementBefore (STMDB): "
                        "array type does not have constant size")
                    return default()

                arraysize = arraytype.size_value()

                elttype = astree.resolve_type(arraytype.tgttyp)
                eltsize = astree.type_size_in_bytes(elttype)
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
                astree.add_local_vardefinition(iaddr, str(hl_asg.lhs), hl_asg.rhs)
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
