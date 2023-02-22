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
    import chb.arm.ARMDictionary


@armregistry.register_tag("UXTH", ARMOpcode)
class ARMUnsignedExtendHalfword(ARMOpcode):
    """Extracts a 16-bit value from a register, zero-extends it, and writes it to a register.

    UXTH<c> <Rd>, <Rm>{, <rotation>}

    tags[1]: <c>
    args[0]: index of op1 in armdictionary
    args[1]: index of op2 in armdictionary
    args[2]: thumb wide

    xdata format: a:vxxxrdh
    -----------------------
    vars[0]: lhs
    xprs[0]: xrm
    xprs[1]: xrm & 65535
    xprs[2]: xrm & 65535 (simplified)
    rdefs[0]: rm
    rdefs[1..]: xrm 65535 (simplified)
    uses[0]: lhs
    useshigh[0]: lhs
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(i) for i in self.args[:-1]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return self.operands

    def annotation(self, xdata: InstrXData) -> str:
        lhs = str(xdata.vars[0])
        result = xdata.xprs[1]
        rresult = xdata.xprs[2]
        xresult = simplify_result(xdata.args[2], xdata.args[3], result, rresult)
        return lhs + " := " + xresult

    def assembly_ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:

        annotations: List[str] = [iaddr, "UXTH"]

        (rhs, preinstrs, postinstrs) = self.operands[1].ast_rvalue(astree)
        (lhs, _, _) = self.operands[0].ast_lvalue(astree)
        assign = astree.mk_assign(
            lhs, rhs, iaddr=iaddr, bytestring=bytestring, annotations=annotations)
        return preinstrs + [assign] + postinstrs

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "UXTH"]

        (ll_rhs, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        lhs = xdata.vars[0]
        rhs = xdata.xprs[2]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        hl_rhss = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)
        if len(hl_rhss) == 1 and len(hl_lhss) == 1:

            hl_lhs = hl_lhss[0]
            hl_rhs = hl_rhss[0]

            if astree.has_variable_intro(iaddr):
                vname = astree.get_variable_intro(iaddr)
                vinfo = astree.mk_vinfo(
                    vname,
                    vtype=astree.astree.unsigned_short_type,
                    vdescr="intro")
                vinfolval = astree.mk_vinfo_lval(vinfo)
                vinfolvalexpr = astree.mk_lval_expr(vinfolval)

                hl_intro_assign = astree.mk_assign(
                    vinfolval,
                    hl_rhs,
                    iaddr=iaddr,
                    bytestring=bytestring,
                    annotations=annotations)

                hl_assign = astree.mk_assign(
                    hl_lhs,
                    vinfolvalexpr,
                    iaddr=iaddr,
                    bytestring=bytestring,
                    annotations=annotations)

                astree.add_reg_definition(iaddr, hl_lhs, vinfolvalexpr)
                astree.add_instr_mapping(hl_intro_assign, ll_assign)
                astree.add_instr_mapping(hl_assign, ll_assign)
                astree.add_instr_address(hl_intro_assign, [iaddr])
                astree.add_instr_address(hl_assign, [iaddr])
                astree.add_expr_mapping(hl_rhs, ll_rhs)
                astree.add_expr_mapping(vinfolvalexpr, ll_rhs)
                astree.add_lval_mapping(hl_lhs, ll_lhs)
                astree.add_lval_mapping(vinfolval, ll_lhs)
                astree.add_expr_reachingdefs(ll_rhs, [rdefs[0]])
                astree.add_lval_defuses(hl_lhs, defuses[0])
                astree.add_lval_defuses(vinfolval, defuses[0])
                astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])
                astree.add_lval_defuses_high(vinfolval, defuseshigh[0])

                return ([hl_intro_assign, hl_assign], [ll_assign])

            else:

                hl_assign = astree.mk_assign(
                    hl_lhs,
                    hl_rhs,
                    iaddr=iaddr,
                    bytestring=bytestring,
                    annotations=annotations)

                astree.add_reg_definition(iaddr, hl_lhs, hl_rhs)
                astree.add_instr_mapping(hl_assign, ll_assign)
                astree.add_instr_address(hl_assign, [iaddr])
                astree.add_expr_mapping(hl_rhs, ll_rhs)
                astree.add_lval_mapping(hl_lhs, ll_lhs)
                astree.add_expr_reachingdefs(ll_rhs, [rdefs[0]])
                astree.add_expr_reachingdefs(hl_rhs, rdefs[1:])
                astree.add_lval_defuses(hl_lhs, defuses[0])
                astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

                return ([hl_assign], [ll_assign])

        else:
            raise UF.CHBError(
                "ARMUnsignedExtendHalfword: multiple expressions/lvals in ast")
