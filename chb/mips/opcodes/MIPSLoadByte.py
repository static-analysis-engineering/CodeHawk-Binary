# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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

from chb.invariants.XXpr import XXpr

from chb.mips.MIPSDictionaryRecord import mipsregistry
from chb.mips.MIPSOpcode import MIPSOpcode, simplify_result
from chb.mips.MIPSOperand import MIPSOperand

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.mips.simulation.MIPSimulationState import MIPSimulationState


@mipsregistry.register_tag("lb", MIPSOpcode)
class MIPSLoadByte(MIPSOpcode):
    """LB rt, offset(base)

    Load a byte from memory as a signed value.

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
        return lhs + ' := ' + rhs

    @property
    def dst_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    @property
    def src_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    # --------------------------------------------------------------------------
    # Operation:
    #   vAddr <- sign_extend(offset) + GPR[base]
    #   (pAddr, CCA) <- AddressTranslation (vAddr, DATA, LOAD)
    #   pAddr <- pAddr[PSIZE-1..2] || (pAddr[1..0] xor ReverseEndian[2])
    #   memword <- LoadMemory (CCA, BYTE, pAddr, vAddr, DATA)
    #   byte <- vAddr[1..0] xor BigEndianCPU[2]
    #   GPR[t] <- sign_extend(memwor[7+8*byte..8*byte])
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "MIPSimulationState") -> str:
        dstop = self.dst_operand
        srcop = self.src_operand
        srcval = simstate.get_rhs(iaddr, srcop, opsize=1)
        if srcval.is_symbolic:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ('encountered symbolic value in lb: '
                 + str(srcval)
                 + ' at address: '
                 + str(srcop)))
        elif srcval.is_defined and srcval.is_literal:
            srcval = cast(SV.SimLiteralValue, srcval)
            srcval = srcval.sign_extend(4)
        else:
            srcval = SV.simUndefinedDW
        lhs = simstate.set(iaddr, dstop, srcval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr, simstate, lhs, srcval)
