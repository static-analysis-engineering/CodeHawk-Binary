# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
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

from typing import cast, List, Optional, Sequence, TYPE_CHECKING

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree
from chb.app.ASTNode import ASTInstruction, ASTExpr, ASTLval

from chb.app.InstrXData import InstrXData

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

from chb.mips.MIPSDictionaryRecord import mipsregistry
from chb.mips.MIPSOpcode import MIPSOpcode, simplify_result

from chb.util.IndexedTable import IndexedTableValue

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.mips.MIPSDictionary import MIPSDictionary


class MIPSBranchOpcode(MIPSOpcode):

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    def has_branch_condition(self) -> bool:
        return True

    def branch_condition(self, xdata: InstrXData) -> XXpr:
        return xdata.xprs[1]

    def ft_conditions(self, xdata: InstrXData) -> Sequence[XXpr]:
        return []

    def assembly_ast(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[ASTInstruction]:
        return []

    def assembly_ast_condition(
            self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Optional[ASTExpr]:
        ftconds = self.ft_conditions(xdata)
        if len(ftconds) == 2:
            tcond = ftconds[1]
            astconds = XU.xxpr_to_ast_exprs(tcond, astree)
            if len(astconds) > 1:
                raise UF.CHBError(
                    "Multiple expressions for MIPS condition")
            else:
                astcond = astconds[0]
                # astree.add_instruction_span(astcond.id, iaddr, bytestring)
                return astcond
        else:
            return None
