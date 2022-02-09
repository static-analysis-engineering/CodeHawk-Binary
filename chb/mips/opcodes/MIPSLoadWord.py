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

from typing import cast, Dict, List, Mapping, Sequence, TYPE_CHECKING

from chb.app.AbstractSyntaxTree import AbstractSyntaxTree

import chb.app.ASTNode as AST

from chb.app.InstrXData import InstrXData

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

from chb.mips.MIPSDictionaryRecord import mipsregistry
from chb.mips.MIPSOpcode import MIPSOpcode, simplify_result
from chb.mips.MIPSOperand import MIPSOperand

import chb.invariants.XXprUtil as XU

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.simulation.SimulationState import SimulationState


@mipsregistry.register_tag("lw", MIPSOpcode)
class MIPSLoadWord(MIPSOpcode):
    """LW rt, offset(base)

    Load a word from memory as a signed value.

    args[0]: index of rt in mips dictionary
    args[1]: index of offset(base) in mips dictionary
    """

    def __init__(
            self,
            mipsd: "MIPSDictionary",
            ixval: IndexedTableValue) -> None:
        MIPSOpcode.__init__(self, mipsd, ixval)

    @property
    def operands(self) -> Sequence[MIPSOperand]:
        return [self.mipsd.mips_operand(i) for i in self.args]

    def load_address(self, xdata: InstrXData) -> XXpr:
        return xdata.xprs[1]

    def global_variables(self, xdata: InstrXData) -> Mapping[str, int]:
        return xdata.xprs[0].global_variables()

    def annotation(self, xdata: InstrXData) -> str:
        """data format a:vxa

        vars[0]: lhs
        xprs[0]: rhs
        xprs[1]: address expr of memory location
        """

        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[0])
        if rhs == '?' and len(xdata.xprs) == 3:
            rhs = '*(' + str(xdata.xprs[1]) + ')'
        return lhs + ' := ' + rhs

    def ast(self,
            astree: AbstractSyntaxTree,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        rhs = XU.xxpr_to_ast_expr(xdata.xprs[1], astree)
        lhs = XU.xvariable_to_ast_lval(xdata.vars[0], astree)
        assign = astree.mk_assign(lhs, rhs)
        astree.add_instruction_span(assign.id, iaddr, bytestring)
        return [assign]

    def is_restore_register(self) -> bool:
        return (self.dst_operand.is_mips_register
                and self.src_operand.is_mips_indirect_register_with_reg('sp'))

    @property
    def src_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    @property
    def dst_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   vAddr <- sign_extend(offset) + GPR[base]
    #   if vAddr[1..0] <> a[2] then
    #      SignalException(AddressError)
    #   endif
    #   (pAddr, CCA) <- AddressTranslation (vAddr, DATA, LOAD)
    #   memword <- LoadMemory (CCA, WORD, pAddr, vAddr, DATA)
    #   GPR[rt] <- memword
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        dstop = self.dst_operand
        srcop = self.src_operand
        srcval = simstate.rhs(iaddr, srcop)
        try:
            intermediates = (
                'val(' + str(simstate.lhs(iaddr, srcop)) + ') = ' + str(srcval))
        except Exception:
            intermediates = ''
        lhs = simstate.set(iaddr, dstop, srcval)
        simstate.increment_programcounter()
        return SU.simassign(iaddr, simstate, lhs, srcval, intermediates)
