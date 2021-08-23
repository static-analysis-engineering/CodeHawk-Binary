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

from chb.invariants.XVariable import XVariable
from chb.invariants.XXpr import XXpr

from chb.mips.MIPSDictionaryRecord import mipsregistry
from chb.mips.MIPSOpcode import MIPSOpcode, simplify_result
from chb.mips.MIPSOperand import MIPSOperand

from chb.mips.simulation.MIPSimLocation import MIPSimMemoryLocation

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.mips.MIPSDictionary import MIPSDictionary
    from chb.simulation.SimulationState import SimulationState


@mipsregistry.register_tag("swr", MIPSOpcode)
class MIPSStoreWordRight(MIPSOpcode):
    """SWR rt, offset(base)

    Store Word Right.
    Store the least-significant part of a word to an unaligned memory address.

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

    @property
    def src_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    @property
    def dst_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #    vAddr <- sign_extend(offset) + GPR[base]
    #    (pAddr, CCA) <- AddressTranslation (vAddr, DATA, STORE)
    #    pAddr <- pAddr[PSIZE-1..2] || (pAddr[1..0] xor ReverseEndian[2])
    #    if BigEndianMem = 0 then
    #       pAddr <- pAddr[PSIZE-1..2] || 0[2]
    #    endif
    #    byte <- vAddr[1..0] xor BigEndianCPU[2]
    #    dataword <- GPR[rt][31-8*byte] || 0[8*byte]
    #    StoreMemory (CCA, WORD-byte, dataword, pAddr, vAddr, DATA)
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "SimulationState") -> str:
        dstop = self.dst_operand
        srcop = self.src_operand
        srcval = simstate.rhs(iaddr, srcop)
        dstlocation = simstate.lhs(iaddr, dstop)
        if dstlocation.is_memory_location:
            dstlocation = cast(MIPSimMemoryLocation, dstlocation)
            if dstlocation.is_global:
                dstaddr = dstlocation.simaddress
                alignment = dstaddr.offsetvalue % 4
            elif dstlocation.is_stack:
                dstaddr = dstlocation.simaddress
                alignment = dstaddr.offsetvalue % 4
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    ('Store-word-right destination is not a memory location: '
                     + str(dstlocation)))
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ('Store-word-right destination is not a memory location: '
                 + str(dstlocation)))

        if not (srcval.is_doubleword and srcval.is_literal and srcval.is_defined):
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ("Store-word-right src value does not have a defined literal value: "
                 + str(srcval)))
        srcval = cast(SV.SimDoubleWordValue, srcval)
        if simstate.bigendian:
            if alignment == 0:
                simstate.set_memval(iaddr, dstaddr, srcval.simbyte4)
            elif alignment == 1:
                simstate.set_memval(iaddr, dstaddr, srcval.simbyte4)
                simstate.set_memval(iaddr, dstaddr.add_offset(1), srcval.simbyte3)
            elif alignment == 2:
                simstate.set_memval(iaddr, dstaddr, srcval.simbyte4)
                simstate.set_memval(iaddr, dstaddr.add_offset(1), srcval.simbyte3)
                simstate.set_memval(iaddr, dstaddr.add_offset(2), srcval.simbyte2)
            elif alignment == 3:
                simstate.set(iaddr, self.dst_operand, srcval)
            else:
                pass
        else:
            if alignment == 0:
                simstate.set(iaddr, self.dst_operand, srcval)
            elif alignment == 1:
                simstate.set_memval(iaddr, dstaddr.add_offset(-2), srcval.simbyte2)
                simstate.set_memval(iaddr, dstaddr.add_offset(-1), srcval.simbyte3)
                simstate.set_memval(iaddr, dstaddr, srcval.simbyte4)
            elif alignment == 2:
                simstate.set_memval(iaddr, dstaddr.add_offset(-1), srcval.simbyte3)
                simstate.set_memval(iaddr, dstaddr, srcval.simbyte4)
            elif alignment == 1:
                simstate.set_memval(iaddr, dstaddr, srcval.simbyte4)
            else:
                pass
        simstate.increment_programcounter()
        return 'assign ' + str(dstlocation)
