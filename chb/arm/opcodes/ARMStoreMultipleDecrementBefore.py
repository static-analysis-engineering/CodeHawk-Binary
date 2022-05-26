# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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

from typing import cast, List, TYPE_CHECKING

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
    args[4]: thumb-wide
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 5, "StoreMultipleDecrementBefore")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[1:-1]]

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxx .

        vars[0..n-1]: lhs expressions
        xprs[0..n-1]: rhs expressions
        xprs[n]: initial value of base register
        """

        return (
            "; ".join(
                str(v)
                + " := "
                + str(x) for (v, x) in zip(xdata.vars, xdata.xprs[:-1])))

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
            instrs.append(astree.mk_assign(lhs, rhs, annotations=annotations))
            reg_offset -= 4
        if self.args[0] == 1:
            reg_decr_c = astree.mk_integer_constant(reg_decr)
            reg_rhs = astree.mk_binary_op("minus", regrval, reg_decr_c)
            instrs.append(astree.mk_assign(
                reglval, reg_rhs, annotations=annotations))
        for assign in instrs:
            astree.add_instruction_span(assign.assembly_xref, iaddr, bytestring)
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

        rhss = XU.xxpr_list_to_ast_exprs(xprs, astree)

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
                            rhs0 = cast(AST.ASTLvalExpr, rhss[0])
                            rhslval = astree.mk_lval(rhs0.lval.lhost, fieldoffset)
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

        for instr in instrs:
            astree.add_instruction_span(instr.assembly_xref, iaddr, bytestring)
        return instrs
