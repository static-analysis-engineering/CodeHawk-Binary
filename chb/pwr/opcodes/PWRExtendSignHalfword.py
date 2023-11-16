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

import chb.invariants.XXpr as X
import chb.invariants.XXprUtil as XU

from chb.pwr.PowerDictionaryRecord import pwrregistry
from chb.pwr.PowerOpcode import PowerOpcode
from chb.pwr.PowerOperand import PowerOperand

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.pwr.PowerDictionary import PowerDictionary


@pwrregistry.register_tag("extsh", PowerOpcode)
@pwrregistry.register_tag("se_extsh", PowerOpcode)
class PWRExtendSignHalfword(PowerOpcode):
    """Extend half word to word, preserving the sign

    extsh rA, rS

    tags[1]: instruction type
    args[0]: set condition register bit if 1
    args[1]: index of rA in pwrdictionary
    args[2]: index of rS in pwrdictionary
    args[3]: index of cr in pwrdictionary

    xdata format:
    -------------
    vars[0]: rA
    xprs[0]: rS
    xprs[1]: rS rewritten
    """

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOpcode.__init__(self, pwrd, ixval)

    @property
    def operands(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(self.args[i]) for i in [1, 2]]

    @property
    def opargs(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(i) for i in self.args[1:]]

    def annotation(self, xdata: InstrXData) -> str:
        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[1])
        return lhs + " := " + rhs

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "extsh"]

        lhs = xdata.vars[0]
        rhs = xdata.xprs[0]
        rdefs = xdata.reachingdefs[0]
        defuses = xdata.defuses[0]
        defuseshigh = xdata.defuseshigh[0]

        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)
        (ll_rhs, _, _) = self.opargs[1].ast_rvalue(astree)
        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        hl_lhss = XU.xvariable_to_ast_lvals (lhs, xdata, astree)
        hl_rhss = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)

        if len(hl_lhss) != 1 or len(hl_rhss) != 1:
            raise UF.CHBError(
                "PWRExtendSignHalfword: multiple lval/expressions in ast")

        hl_lhs = hl_lhss[0]
        hl_rhs = hl_rhss[0]

        return self.ast_variable_intro(
            astree,
            iaddr,
            annotations,
            bytestring,
            hl_lhs,
            hl_rhs,
            ll_lhs,
            ll_rhs,
            hl_rdefs=[rdefs],
            ll_rdefs=[rdefs],
            defuses=defuses,
            defuseshigh=defuseshigh)


        '''
        assign(
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
        astree.add_expr_reachingdefs(ll_rhs, [rdefs])
        astree.add_lval_defuses(hl_lhs, defuses)
        astree.add_lval_defuses_high(hl_lhs, defuseshigh)

        return ([hl_assign], [ll_assign])
        '''
