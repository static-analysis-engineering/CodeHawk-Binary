# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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

from typing import cast, List, Tuple, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("LDREX", ARMOpcode)
class ARMLoadRegisterExclusive(ARMOpcode):
    """Loads a word from memory and writes it to a register and signals exclusive access.

    LDR<c> <Rt>, [<base>, <offset>]

    tags[1]: <c>
    args[0]: index of destination operand in armdictionary
    args[1]: index of base register in armdictionary
    args[2]: index of index in armdictionary
    args[3]: index of memory location in armdictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "LoadRegisterExclusive")

    @property
    def operands(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 3]]

    @property
    def opargs(self) -> List[ARMOperand]:
        return [self.armd.arm_operand(self.args[i]) for i in [0, 1, 2, 3]]


    def is_load_instruction(self, xdata: InstrXData) -> bool:
        return True

    def rhs(self, xdata: InstrXData) -> List[XXpr]:
        return [xdata.xprs[1]]

    def annotation(self, xdata: InstrXData) -> str:
        """xdata format: a:vxx .

        vars[0]: lhs
        xprs[0]: value in memory location
        xprs[1]: value in memory location (simplified)
        """

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

        lhs = xdata.vars[0]
        rhs = xdata.xprs[3]
        memaddr = xdata.xprs[4]
        rdefs = xdata.reachingdefs
        defuses = xdata.defuses
        defuseshigh = xdata.defuseshigh

        annotations: List[str] = [iaddr, "LDREX", "addr:" + str(memaddr)]

        (ll_rhs, _, _) = self.opargs[3].ast_rvalue(astree)
        (ll_op1, _, _) = self.opargs[1].ast_rvalue(astree)
        (ll_op2, _, _) = self.opargs[2].ast_rvalue(astree)
        (ll_lhs, _, _) = self.opargs[0].ast_lvalue(astree)

        hl_rhss = XU.xxpr_to_ast_exprs(rhs, xdata, iaddr, astree)
        if len(hl_rhss) == 0:
            chklogger.logger.warning(
                "LDREX at address %s: no rhs value found", iaddr)

        if len(hl_rhss) > 1:
            chklogger.logger.warning(
                "LDREX at address %s: multiple rhs values: %s",
                iaddr,
                ", ".join(str(x) for x in hl_rhss))
            hl_rhs = None

        if (
                len(hl_rhss) != 1
                or rhs.is_tmp_variable
                or rhs.has_unknown_memory_base()):
            addrlval = XU.xmemory_dereference_lval(memaddr, xdata, iaddr, astree)
            hl_rhs = astree.mk_lval_expression(addrlval)

        else:
            hl_rhs = hl_rhss[0]
            if str(hl_rhs).startswith("localvar"):
                deflocs = xdata.reachingdeflocs_for_s(str(rhs))
                if len(deflocs) == 1:
                    definition = astree.localvardefinition(
                        str(deflocs[0]), str(hl_rhs))
                    if definition is not None:
                        hl_rhs = definition

        hl_lhss = XU.xvariable_to_ast_lvals(lhs, xdata, astree)
        if len(hl_lhss) == 0:
            raise UF.CHBError("LDR: no lval found")
        if len(hl_lhss) > 1:
            raise UF.CHBError(
                "LDR: multiple lvals: "
                + ", ".join(str(v) for v in hl_lhss))

        hl_lhs = hl_lhss[0]

        return self.ast_variable_intro(
            astree,
            hl_rhs.ctype(astree.ctyper),
            hl_lhs,
            hl_rhs,
            ll_lhs,
            ll_rhs,
            rdefs[3:],
            rdefs[:3],
            defuses[0],
            defuseshigh[0],
            True,
            iaddr,
            annotations,
            bytestring)
