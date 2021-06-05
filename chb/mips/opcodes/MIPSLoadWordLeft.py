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
    from chb.mips.simulation.MIPSimulationState import MIPSimulationState


@mipsregistry.register_tag("lwl", MIPSOpcode)
class MIPSLoadWordLeft(MIPSOpcode):
    """LWL rt, offset(base)

    Load Word Left
    Load the most significant part of a word as a signed value from an
    unaligned memory address.

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
        xprs[1]: address of memory location
        """

        lhs = str(xdata.vars[0])
        rhs = str(xdata.xprs[0])
        return lhs + ' := ' + rhs

    @property
    def src_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[1])

    @property
    def dst_operand(self) -> MIPSOperand:
        return self.mipsd.mips_operand(self.args[0])

    # --------------------------------------------------------------------------
    # Operation:
    #   vAddr <- sign_extend(offset) + GPR[base]
    #   (pAddr, CCA) <- AddressTranslation (vAddr, DATA, LOAD)
    #   pAddr <- pAddr[PSIZE-1..2] || (pAddr[1..0] xor ReverseEndian[2])
    #   if BigEndianMem = 0 then
    #      pAddr <- pAddr[PSIZE-1..2] || 0[2]
    #   endif
    #   byte <- vAddr[1..0] xor BigEndianCPU[2]
    #   memword <- LoadMemory (CCA, byte, pAdr, vAddr, DATA)
    #   temp <- memword[7+8*byte..0] || GPR[rt][23-8*byte..0]
    #   GPR[rt] <- temp
    # --------------------------------------------------------------------------
    def simulate(self, iaddr: str, simstate: "MIPSimulationState") -> str:
        srcop = self.src_operand
        srclocation = simstate.get_lhs(iaddr, srcop)
        if srclocation.is_memory_location:
            srclocation = cast(MIPSimMemoryLocation, srclocation)
            if srclocation.is_global or srclocation.is_stack:
                srcaddress = srclocation.simaddress
                alignment = srcaddress.alignment
            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    ('Load-word-left source is not a memory location: '
                     + str(srclocation)))
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                ('Load-word-left source is not a memory location: '
                 + str(srclocation)))

        dstop = self.dst_operand
        dstvalue = simstate.get_rhs(iaddr, dstop)
        if dstvalue.is_defined and dstvalue.is_literal and dstvalue.is_doubleword:
            dstvalue = cast(SV.SimDoubleWordValue, dstvalue)
        else:
            dstvalue = SV.simUndefinedDW

        # bytes are set in the destination value with b1 = lsf byte, etc.
        if simstate.bigendian:
            if alignment == 0:
                dstval = simstate.get_rhs(iaddr, srcop)
                lhs = simstate.set(iaddr, dstop, dstval)
            elif alignment == 1:   # set byte1, byte2, byte3
                b4 = simstate.get_memval(iaddr, srcaddress, 1)
                b3 = simstate.get_memval(iaddr, srcaddress.add_offset(1), 1)
                b2 = simstate.get_memval(iaddr, srcaddress.add_offset(2), 1)
                b4 = cast(SV.SimByteValue, b4)
                b3 = cast(SV.SimByteValue, b3)
                b2 = cast(SV.SimByteValue, b2)
                dstval = dstvalue.set_byte2(b2).set_byte3(b3).set_byte4(b4)
                lhs = simstate.set(iaddr, dstop, dstval)
            elif alignment == 2:   # set byte1, byte2
                b4 = simstate.get_memval(iaddr, srcaddress, 1)
                b3 = simstate.get_memval(iaddr, srcaddress.add_offset(1), 1)
                b4 = cast(SV.SimByteValue, b4)
                b3 = cast(SV.SimByteValue, b3)
                dstval = dstvalue.set_byte3(b3).set_byte4(b4)
                lhs = simstate.set(iaddr, dstop, dstval)
            elif alignment == 3:   # set byte1
                b4 = simstate.get_memval(iaddr, srcaddress, 1)
                b4 = cast(SV.SimByteValue, b4)
                dstval = dstvalue.set_byte4(b4)
                lhs = simstate.set(iaddr, dstop, dstval)
            else:
                pass
        else:
            if alignment == 0:     # set byte 1
                b1 = simstate.get_memval(iaddr, srcaddress, 1)
                b1 = cast(SV.SimByteValue, b1)
                dstval = dstvalue.set_byte1(b1)
                lhs = simstate.set(iaddr, dstop, dstval)
            elif alignment == 1:   # set byte1, byte2
                b1 = simstate.get_memval(iaddr, srcaddress.add_offset(-1), 1)
                b2 = simstate.get_memval(iaddr, srcaddress, 1)
                b1 = cast(SV.SimByteValue, b1)
                b2 = cast(SV.SimByteValue, b2)
                dstval = dstvalue.set_byte1(b1).set_byte2(b2)
                lhs = simstate.set(iaddr, dstop, dstval)
            elif alignment == 2:   # set byte1, byte2, byte3
                b1 = simstate.get_memval(iaddr, srcaddress.add_offset(-2), 1)
                b2 = simstate.get_memval(iaddr, srcaddress.add_offset(-1), 1)
                b3 = simstate.get_memval(iaddr, srcaddress, 1)
                b1 = cast(SV.SimByteValue, b1)
                b2 = cast(SV.SimByteValue, b2)
                b3 = cast(SV.SimByteValue, b3)
                dstval = dstvalue.set_byte1(b1).set_byte2(b2).set_byte3(b3)
                lhs = simstate.set(iaddr, dstop, dstval)
            elif alignment == 3:
                dstval = simstate.get_rhs(iaddr, srcop)
                lhs = simstate.set(iaddr, dstop, dstval)
        simstate.increment_program_counter()
        return SU.simassign(iaddr, simstate, lhs, dstval)
