# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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

from typing import cast, List, Sequence, Optional, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.invariants.XXprUtil as XU

from chb.pwr.PowerDictionaryRecord import pwrregistry
from chb.pwr.PowerOpcode import PowerOpcode
from chb.pwr.PowerOperand import PowerOperand

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.pwr.PowerDictionary import PowerDictionary

@pwrregistry.register_tag("lbz", PowerOpcode)
@pwrregistry.register_tag("lbzu", PowerOpcode)
@pwrregistry.register_tag("e_lbz", PowerOpcode)
@pwrregistry.register_tag("e_lbzu", PowerOpcode)
@pwrregistry.register_tag("se_lbz", PowerOpcode)
class PWRLoadByteZero(PowerOpcode):
    """The byte addressed by the effective address is loaded into the destination.

    lbz   rD,D(rA)
    lbzu  rD,D(rA)

    tags[1]: pit: instruction type
    args[0]: u: update address register if 1
    args[1]: index of destination register (rD) in pwrdictionary
    args[2]: index of address register (rA) in pwrdictionary
    args[3]: index of memory location (D(rA)) in pwrdictionary

    xdata format:
    -------------
    vars[0]: rD
    vars[1]: memory location to load from
    xprs[0]: rA
    xprs[1]: memory value
    xprs[2]: memory value rewritten
    xprs[3]: memory address
    rdefs[0]: reaching definition of rA
    rdefs[1]: reaching definition for memory value
    defuses[0]: uses of rD
    defuseshigh[0]: uses of rD in high-level expressions
    """

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOpcode.__init__(self, pwrd, ixval)

    @property
    def operands(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(self.args[i]) for i in [1, 3]]

    @property
    def opargs(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(i) for i in self.args[1:]]

    def annotation(self, xdata: InstrXData) -> str:
        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[2])
        return lhs + " := " + rhs

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, self.tags[0]]

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs, ll_pre, ll_post) = self.opargs[2].ast_rvalue(astree)

        lhs = xdata.vars[0]
        rhs = xdata.xprs[2]
        memaddr = xdata.xprs[3]
        rdefs = xdata.reachingdefs
        uses = xdata.defuses
        useshigh = xdata.defuseshigh

        hl_rhss = XU.xxpr_to_ast_exprs(rhs, xdata, iaddr, astree)

        if len(hl_rhss) != 1 or rhs.is_tmp_variable or rhs.has_unknown_memory_base():
            addrlval = XU.xmemory_dereference_lval(memaddr, xdata, iaddr, astree)
            hl_rhs = astree.mk_lval_expression(addrlval)

        else:
            hl_rhs = hl_rhss[0]
            if str(hl_rhs).startswith("localvar"):
                deflocs = xdata.reachingdeflocs_for_s(str(rhs))
                if len(deflocs) == 1:
                    definition = astree.localvardefinition(str(deflocs[0]), str(hl_rhs))
                    if definition is not None:
                        hl_rhs = definition

        hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        hl_lhs = hl_lhss[0]

        return self.ast_variable_intro(
            astree,
            iaddr,
            annotations,
            bytestring,
            hl_lhs,
            hl_rhs,
            ll_lhs,
            ll_rhs,
            hl_rdefs=[rdefs[1]],
            ll_rdefs=[rdefs[0]],
            defuses=uses[0],
            defuseshigh=useshigh[0])

    '''
        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs, ll_pre, ll_post) = self.opargs[2].ast_rvalue(astree)
        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        lhs = xdata.vars[0]
        rhs = xdata.xprs[2]
        memaddr = xdata.xprs[3]
        rdefs = xdata.reachingdefs
        uses = xdata.defuses
        useshigh = xdata.defuseshigh

        rhsexprs = XU.xxpr_to_ast_exprs(rhs, xdata, iaddr, astree)
        if len(rhsexprs) != 1:
            raise UF.CHBError(
                "LoadByteZero: no or multiple rhs values at: " + iaddr)
        hl_rhs = rhsexprs[0]

        hl_lhs = astree.mk_register_variable_lval(str(lhs))
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
        astree.add_expr_reachingdefs(hl_rhs, [rdefs[1]])
        astree.add_lval_defuses(hl_lhs, uses[0])
        astree.add_lval_defuses_high(hl_lhs, useshigh[0])

        if ll_rhs.is_ast_lval_expr:
            lvalexpr = cast(AST.ASTLvalExpr, ll_rhs)
            if lvalexpr.lval.lhost.is_memref:
                memexp = cast(AST.ASTMemRef, lvalexpr.lval.lhost).memexp
                astree.add_expr_reachingdefs(memexp, [rdefs[0], rdefs[1]])

        return ([hl_assign], [ll_assign])
    '''
