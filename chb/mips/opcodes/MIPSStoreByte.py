# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
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

from typing import cast, Dict, List, Mapping, Sequence, TYPE_CHECKING

from chb.app.InstrXData import InstrXData
from chb.app.MemoryAccess import MemoryAccess

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

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


@mipsregistry.register_tag("sb", MIPSOpcode)
class MIPSStoreByte(MIPSOpcode):
    """SB rt, offset(base)

    Store a byte to memory.

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

    def is_stack_access(self, xdata: InstrXData) -> bool:
        return xdata.xprs[2].is_stack_address

    def is_store_instruction(self, xdata: InstrXData) -> bool:
        return True

    def memory_accesses(self, xdata: InstrXData) -> Sequence[MemoryAccess]:
        return [MemoryAccess(xdata.xprs[2], "W", size=1)]

    def global_variables(self, xdata: InstrXData) -> Mapping[str, int]:
        return xdata.xprs[0].global_variables()

    def annotation(self, xdata: InstrXData) -> str:
        """data format a:vxxa

        vars[0]: lhs
        xprs[0]: rhs
        xprs[1]: rhs (simplified)
        xprs[2]: address of memory location
        """

        lhs = str(xdata.vars[0])
        rhs = xdata.xprs[0]
        rrhs = xdata.xprs[1]
        xrhs = simplify_result(xdata.args[1], xdata.args[2], rhs, rrhs)
        return lhs + ' := ' + xrhs

    def ast(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> List[AST.ASTInstruction]:
        rhss = XU.xxpr_to_ast_exprs(xdata.xprs[1], xdata, iaddr, astree)
        lhss = XU.xvariable_to_ast_lvals(xdata.vars[0], xdata, astree)
        if len(rhss) == 1 and len(lhss) == 1:
            rhs = rhss[0]
            lhs = lhss[0]
            assign = astree.mk_assign(lhs, rhs)
            astree.add_instruction_span(assign.locationid, iaddr, bytestring)
            return [assign]
        else:
            raise UF.CHBError(
                "MIPSStoreByte: multiple expressions/lvals in ast")

    @property
    def src_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    @property
    def dst_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   vAddr <- sign_extend(offset) + GPR(base)
    #   (pAddr, CCA) <- AddressTranslation (vAddr, DATA, STORE)
    #   pAddr <- pAddr[PSIZE-1..2] || (pAddr[1..0] xor ReverseEndian[2])
    #   bytesel <- vAddr[1..] xor BigEndianCPU[2]
    #   dataword <- GPR[rt][31-8*bytesel..0] || 0[8*bytesel]
    #   StoreMemory (CCA, BYTE, dataword, pAddr, vAddr, DATA)
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        dstop = self.dst_operand
        srcop = self.src_operand
        srcval = simstate.rhs(iaddr, srcop, opsize=1)
        lhs = simstate.set(iaddr, dstop, srcval)
        simstate.increment_programcounter()
        return SU.simassign(iaddr, simstate, lhs, srcval)
