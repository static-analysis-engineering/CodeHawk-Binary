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
from codecs import decode
import struct

from typing import cast, List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

from chb.invariants.XXpr import XprConstant
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMVfpDatatype import ARMVfpDatatype    


@armregistry.register_tag("VMOVDDS", ARMOpcode)
class ARMVectorMoveDDS(ARMOpcode):
    """Copies two words from a doubleword extension register into two arm registers.

    VMOV<c> <Rt>, <Rt2>, <Dm>

    tags[1]: <c>
    args[0]: index of vfp-data type in armdictionary (not used)
    args[1]: index of first destination in armdictionary
    args[2]: index of second destination in armdictionary
    args[3]: index of combined destination armdictionary
    args[4]: index of source in armdictionary (optional)

    xdata format:
    -------------
    vars[0]: first destination operand
    vars[1]: second destination operand
    vars[2]: combined destination operand
    xprs[0]: source operand
    xprs[1]: source operand rewritten
    rdefs[0]: reaching definitions for source operand
    uses[0]: uses of first destination operand
    uses[1]: uses of second destination operand
    uses[2]: uses of combined destination operand
    useshigh[0]: uses of first destination in high-level expressions
    useshigh[1]: uses of second destination in high-level expressions
    useshigh[2]: uses of combined destination in high-level expressions
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)

    @property
    def mnemonic(self) -> str:
        return "VMOV"

    def mnemonic_extension(self) -> str:
        cc = ARMOpcode.mnemonic_extension(self)
        vfpdt = str(self.vfp_datatype)
        return cc + vfpdt

    @property
    def vfp_datatype(self) -> "ARMVfpDatatype":
        return self.armd.arm_vfp_datatype(self.args[0])    

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 4]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args]

    def annotation(self, xdata: InstrXData) -> str:
        lhs1 = str(xdata.vars[0])
        lhs2 = str(xdata.vars[1])
        rhs = str(xdata.xprs[1])
        return "(" + lhs1 + ", " + lhs2 + ") := " + rhs
 
    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "VMOV"]

        lhs1 = xdata.vars[0]
        lhs2 = xdata.vars[1]
        lhsc = xdata.vars[2]
        rhs = xdata.xprs[0]
        rdefs = xdata.reachingdefs[0]
        defuses1 = xdata.defuses[0]
        defuses2 = xdata.defuses[1]
        defusesc = xdata.defuses[2]
        defuseshigh1 = xdata.defuseshigh[0]
        defuseshigh2 = xdata.defuseshigh[1]
        defuseshighc = xdata.defuseshigh[2]

        (ll_lhs1, _, _) = self.opargs[1].ast_lvalue(astree)
        (ll_lhs2, _, _) = self.opargs[2].ast_lvalue(astree)
        (ll_lhsc, _, _) = self.opargs[3].ast_lvalue(astree)
        (ll_rhs, _, _) = self.opargs[4].ast_rvalue(astree)

        ll_assign1 = astree.mk_assign(
            ll_lhs1,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        ll_assign2 = astree.mk_assign(
            ll_lhs2,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        ll_assignc = astree.mk_assign(
            ll_lhsc,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)
        
        hl_lhss = XU.xvariable_to_ast_lvals(lhsc, xdata, astree)
        hl_rhss = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)

        if len(hl_lhss) == 1 and len(hl_rhss) == 1:
            hl_lhs = hl_lhss[0]
            hl_rhs = hl_rhss[0]

            if str(hl_lhs).startswith("S") and str(ll_rhs).startswith("R"):
                hl_rhs = astree.mk_cast_expr(astree.astree.float_type, hl_rhs)
            hl_assign = astree.mk_assign(
                hl_lhs,
                hl_rhs,
                iaddr=iaddr,
                bytestring=bytestring,
                annotations=annotations)

            astree.add_reg_definition(iaddr, hl_lhs, hl_rhs)
            astree.add_instr_mapping(hl_assign, ll_assign1)
            astree.add_instr_mapping(hl_assign, ll_assign2)
            astree.add_instr_mapping(hl_assign, ll_assignc)            
            astree.add_instr_address(hl_assign, [iaddr])
            astree.add_expr_mapping(hl_rhs, ll_rhs)
            astree.add_lval_mapping(hl_lhs, ll_lhs1)
            astree.add_lval_mapping(hl_lhs, ll_lhs2)
            astree.add_lval_mapping(hl_lhs, ll_lhsc)            
            astree.add_expr_reachingdefs(ll_rhs, [rdefs])
            astree.add_lval_defuses(hl_lhs, defuses1)
            astree.add_lval_defuses(hl_lhs, defuses2)
            astree.add_lval_defuses(hl_lhs, defusesc)            
            astree.add_lval_defuses_high(hl_lhs, defuseshigh1)
            astree.add_lval_defuses_high(hl_lhs, defuseshigh2)
            astree.add_lval_defuses_high(hl_lhs, defuseshighc)

            return ([hl_assign], [ll_assign1, ll_assign2, ll_assignc])

        else:
            raise UF.CHBError(
                "VectorMove (VMOV): multiple lval/expressions in ast")
