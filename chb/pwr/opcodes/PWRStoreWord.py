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

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

from chb.pwr.PowerDictionaryRecord import pwrregistry
from chb.pwr.PowerOpcode import PowerOpcode
from chb.pwr.PowerOperand import PowerOperand

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.pwr.PowerDictionary import PowerDictionary


@pwrregistry.register_tag("stw", PowerOpcode)
@pwrregistry.register_tag("stwu", PowerOpcode)
@pwrregistry.register_tag("e_stw", PowerOpcode)
@pwrregistry.register_tag("e_stwu", PowerOpcode)
class PWRStoreWord(PowerOpcode):
    """Store Word (with update, optional)

    stw  rS,D(rA)
    stwu rS,D(rA)

    tags[1]: instruction type
    args[0]: update if 1
    args[1]: index of rS in pwrdictionary
    args[2]: index of rA in pwrdictionary
    args[3]: index of memory location in pwrdictionary

    xdata format:
    -------------
    vars[0]: memory location where value is stored
    xprs[0]: rS
    xprs[1]: rS rewritten
    xprs[2]: rA
    xprs[3]: rA rewritten
    xprs[4]: address of memory location where value is stored
    rdefs[0]: reaching definition for rS
    rdefs[1]: reaching definition for rA
    uses[0]: use for vmem
    uses[1]: use for ra (if update)
    useshigh[0]: use for vmem
    useshigh[1]: use for ra (if update)
    
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
        rhs = str(xdata.xprs[1])
        return lhs + " := " + rhs

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:

        annotations: List[str] = [iaddr, "stb"]

        (ll_rhs, _, _) = self.opargs[0].ast_rvalue(astree)
        (ll_lhs, ll_preinstrs, ll_postinstrs) = self.opargs[2].ast_lvalue(astree)
        ll_assign = astree.mk_assign(
            ll_lhs,
            ll_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        lhs = xdata.vars[0]
        rhs = xdata.xprs[1]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        hl_rhs = XU.xxpr_to_ast_def_exprs(rhs, xdata, iaddr, astree)[0]

        if lhs.is_tmp or lhs.has_unknown_memory_base():
            hl_lhs = None
            address = xdata.xprs[4]
            astaddrs = XU.xxpr_to_ast_def_exprs(address, xdata, iaddr, astree)
            if len(astaddrs) == 1:
                astaddr = astaddrs[0]
                if astaddr.is_ast_addressof:
                    hl_lhs = cast(AST.ASTAddressOf, astaddr).lval

            if hl_lhs is None:
                hl_lhs = XU.xmemory_dereference_lval(xdata.xprs[4], xdata, iaddr, astree)
            astree.add_lval_store(hl_lhs)

        else:
            lvals = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
            if len(lvals) != 1:
                raise UF.CHBError(
                    "no or multiple lhs values for storebyte at " + iaddr)

            hl_lhs = lvals[0]
            astree.add_lval_store(hl_lhs)

        hl_assign = astree.mk_assign(
            hl_lhs,
            hl_rhs,
            iaddr=iaddr,
            bytestring=bytestring,
            annotations=annotations)

        astree.add_instr_mapping(hl_assign, ll_assign)
        astree.add_instr_address(hl_assign, [iaddr])
        astree.add_expr_mapping(hl_rhs, ll_rhs)
        astree.add_lval_mapping(hl_lhs, ll_lhs)
        astree.add_expr_reachingdefs(ll_rhs, [rdefs[0]])
        astree.add_lval_defuses(hl_lhs, defuses[0])
        astree.add_lval_defuses_high(hl_lhs, defuseshigh[0])

        if ll_lhs.lhost.is_memref:
            memexp = cast(AST.ASTMemRef, ll_lhs.lhost).memexp
            astree.add_expr_reachingdefs(memexp, [rdefs[0], rdefs[1]])

        return ([hl_assign], ll_preinstrs + [ll_assign] + ll_postinstrs)
