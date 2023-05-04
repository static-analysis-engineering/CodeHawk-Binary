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

@pwrregistry.register_tag("subf", PowerOpcode)
@pwrregistry.register_tag("subf.", PowerOpcode)
@pwrregistry.register_tag("subfo", PowerOpcode)
@pwrregistry.register_tag("subfo.", PowerOpcode)
@pwrregistry.register_tag("se_subf", PowerOpcode)
class PWRSubtractFrom(PowerOpcode):
    """Subtract two registers

    addi rD,rA,rB

    tags[1]: pit: instruction type
    args[0]: rc: record condition if 1
    args[1]: oe: overflow detection if 1
    args[2]: rd: index of destination register in pwrdictionary
    args[3]: ra: index of first source register in pwrdictionary
    args[4]: rb: index of second source register in pwrdictionary
    args[5]: cr: index of condition register field in pwrdictionary
    args[6]: so: index of summary overflow bit int pwrdictionary
    args[7]: ov: index of overflow bit in pwrdictionary

    xdata format:
    -------------
    vars[0]: rD
    xprs[0]: rA
    xprs[1]: rB
    xprs[2]: rB - rA
    xprs[3]: (rB - rA) rewritten
    rdefs[0]: reaching definitions for rA
    rdefs[1]: reaching definitions for rB
    uses[0]: uses for rD
    useshigh[0]: uses for rD
    """

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOpcode.__init__(self, pwrd, ixval)

    @property
    def operands(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(self.args[i]) for i in [2, 3, 4]]

    @property
    def opargs(self) -> List[PowerOperand]:
        return [self.pwrd.pwr_operand(i) for i in self.args[2:]]

    def annotation(self, xdata: InstrXData) -> str:
        lhs = str(xdata.vars[0])
        xrhs = str(xdata.xprs[2])
        rxrhs = str(xdata.xprs[3])
        return lhs + " := " + xrhs + " (= " + rxrhs + ")"

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "subf"]

        (ll_lhs, _, _) = self.operands[0].ast_lvalue(astree)
        (ll_op1, _, _) = self.operands[1].ast_rvalue(astree)
        (ll_op2, _, _) = self.operands[2].ast_rvalue(astree)
        ll_rhs = astree.mk_binary_op("minus", ll_op2, ll_op1)

        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        lhs = xdata.vars[0]
        rhs = xdata.xprs[3]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        lhsasts = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        if len(lhsasts) != 1:
            raise UF.CHBError("SubtractFrom: zero or multiple lvals at " + iaddr)

        hl_lhs = lhsasts[0]

        rhsasts = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)
        if len(rhsasts) != 1:
            raise UF.CHBError("SubtractFrom: zero or multiple rhs values at " + iaddr)

        hl_rhs = rhsasts[0]

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
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[0], rdefs[1]])
        astree.add_expr_reachingdefs(ll_op1, [rdefs[0]])
        astree.add_expr_reachingdefs(ll_op2, [rdefs[1]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        return ([hl_assign], [ll_assign])
