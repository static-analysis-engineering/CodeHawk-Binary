# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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

from typing import cast, Dict, List, TYPE_CHECKING

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.simulation.SimulationState import SimulationState


class SimMemoryByteLink(SV.SimByteValue):
    """A location place holder and reference to a symbolic value in memory.

    Arguments:
    - linkedto: the symbolic value that this byte is part of
    - position: the byte position in that symbolic value (0 through 3)
    """

    def __init__(self, linkedto: SSV.SimSymbolicValue, position: int) -> None:
        SV.SimByteValue.__init__(self, 0, defined=False)
        self._linkedto = linkedto
        self._position = position

    @property
    def linkedto(self) -> SSV.SimSymbolicValue:
        return self._linkedto

    @property
    def position(self) -> int:
        return self._position

    def is_link(self) -> bool:
        return True


def mklink(sym: SSV.SimSymbolicValue, pos: int) -> SimMemoryByteLink:
    return SimMemoryByteLink(sym, pos)


class SimMemory(object):
    """A logical chunk of memory, byte-addressed."""

    def __init__(
            self,
            simstate: "SimulationState",
            initialized: bool,
            name: str) -> None:
        self._simstate = simstate
        self._mem: Dict[int, SV.SimByteValue] = {}
        self._initialized = initialized
        self._name = name

    @property
    def simstate(self) -> "SimulationState":
        return self._simstate

    @property
    def name(self) -> str:
        return self._name

    @property
    def initialized(self) -> bool:
        return self._initialized

    @property
    def bigendian(self) -> bool:
        return self.simstate.bigendian

    @property
    def lowaddr(self) -> int:
        if self.size > 0:
            return self.offsets()[0]
        else:
            raise UF.CHBError("Memory is empty")

    @property
    def highaddr(self) -> int:
        if self.size > 0:
            return self.offsets()[-1]
        else:
            raise UF.CHBError("Memory is empty")

    @property
    def size(self) -> int:
        """Return the number of bytes explicitly contained."""

        return len(self._mem)

    def offsets(self) -> List[int]:
        """Return a sorted list of offsets in this memory block."""

        return sorted(list(self._mem.keys()))

    def get_start_address(self) -> int:
        """Return the lowest offset present in this memory block."""

        if self.size > 0:
            return self.lowaddr
        else:
            raise UF.CHBError(self.name + " memory is empty")

    def get_extent(self) -> int:
        """Return the difference between the highest and lowest offset."""

        if self.size > 0:
            return self.highaddr - self.lowaddr
        else:
            raise UF.CHBError(self.name + " memory is empty")

    def set_byte(self, iaddr: str, offset: int, srcval: SV.SimByteValue) -> None:
        """Assigns srcval to the memory location at the given offset."""

        self._mem[offset] = srcval

    def set_symbolic_little_endian(
            self,
            iaddr: str,
            offset: int,
            srcval: SSV.SimSymbolicValue) -> None:
        if srcval.size == 2:
            self.set_byte(iaddr, offset, mklink(srcval, 0))
            self.set_byte(iaddr, offset + 1, mklink(srcval, 1))
        elif srcval.size == 4:
            self.set_byte(iaddr, offset, mklink(srcval, 0))
            self.set_byte(iaddr, offset + 1, mklink(srcval, 1))
            self.set_byte(iaddr, offset + 2, mklink(srcval, 2))
            self.set_byte(iaddr, offset + 3, mklink(srcval, 3))
        else:
            raise UF.CHBError("Symbolic value of size "
                              + str(srcval.size)
                              + " not supported")

    def set_symbolic_big_endian(
            self,
            iaddr: str,
            offset: int,
            srcval: SSV.SimSymbolicValue) -> None:
        if srcval.size == 2:
            self.set_byte(iaddr, offset, mklink(srcval, 1))
            self.set_byte(iaddr, offset + 1, mklink(srcval, 0))
        elif srcval.size == 4:
            self.set_byte(iaddr, offset, mklink(srcval, 3))
            self.set_byte(iaddr, offset + 1, mklink(srcval, 2))
            self.set_byte(iaddr, offset + 2, mklink(srcval, 1))
            self.set_byte(iaddr, offset + 3, mklink(srcval, 0))
        else:
            raise UF.CHBError("Symbolic value of size "
                              + str(srcval.size)
                              + " not supported")

    def set(
            self,
            iaddr: str,
            address: SSV.SimAddress,
            srcval: SV.SimValue) -> None:
        offset = address.offsetvalue
        if srcval.is_symbolic():
            srcval = cast(SSV.SimSymbolicValue, srcval)
            if self.bigendian:
                self.set_symbolic_big_endian(iaddr, offset, srcval)
            else:
                self.set_symbolic_little_endian(iaddr, offset, srcval)
        elif srcval.is_literal():
            srcval = cast(SV.SimLiteralValue, srcval)
            if self.bigendian:
                self.set_big_endian(iaddr, offset, srcval)
            else:
                self.set_little_endian(iaddr, offset, srcval)

    def set_little_endian(
            self,
            iaddr: str,
            offset: int,
            srcval: SV.SimLiteralValue) -> None:
        if srcval.is_byte():
            srcval = cast(SV.SimByteValue, srcval)
            self.set_byte(iaddr, offset, srcval)
        elif srcval.is_word():
            srcval = cast(SV.SimWordValue, srcval)
            self.set_byte(iaddr, offset, srcval.lowbyte)
            self.set_byte(iaddr, offset + 1, srcval.highbyte)
        elif srcval.is_doubleword():
            srcval = cast(SV.SimDoubleWordValue, srcval)
            self.set_byte(iaddr, offset, srcval.simbyte1)
            self.set_byte(iaddr, offset + 1, srcval.simbyte2)
            self.set_byte(iaddr, offset + 2, srcval.simbyte3)
            self.set_byte(iaddr, offset + 3, srcval.simbyte4)
        else:
            raise SU.CHBSimError(
                self.simstate,
                iaddr,
                "Type of srcval not recognized: " + str(srcval))

    def set_big_endian(
            self,
            iaddr: str,
            offset: int,
            srcval: SV.SimLiteralValue) -> None:
        if srcval.is_byte():
            srcval = cast(SV.SimByteValue, srcval)
            self.set_byte(iaddr, offset, srcval)
        elif srcval.is_word():
            srcval = cast(SV.SimWordValue, srcval)
            self.set_byte(iaddr, offset, srcval.highbyte)
            self.set_byte(iaddr, offset + 1, srcval.lowbyte)
        elif srcval.is_doubleword():
            srcval = cast(SV.SimDoubleWordValue, srcval)
            self.set_byte(iaddr, offset, srcval.simbyte4)
            self.set_byte(iaddr, offset + 1, srcval.simbyte3)
            self.set_byte(iaddr, offset + 2, srcval.simbyte2)
            self.set_byte(iaddr, offset + 3, srcval.simbyte1)
        else:
            raise SU.CHBSimError(
                self.simstate,
                iaddr,
                "Type of srcval not recognized: " + str(srcval))

    def get_byte(self, iaddr: str, offset: int) -> SV.SimByteValue:
        if offset in self._mem:
            simbyte = self._mem[offset]
            if simbyte.is_defined():
                return simbyte
            else:
                raise SU.CHBSimError(
                    self.simstate,
                    iaddr,
                    (self.name
                     + " memory location at "
                     + hex(offset)
                     + " is a symbolic value"))
        else:
            if self.initialized:
                return SV.simZerobyte
            else:
                raise SU.CHBSimError(
                    self.simstate,
                    iaddr,
                    (self.name
                     + " memory location at "
                     + str(hex(offset))
                     + " not initialized"))

    def get(
            self,
            iaddr: str,
            address: SSV.SimAddress,
            size: int) -> SV.SimValue:
        offset = address.offsetvalue
        if offset not in self._mem:
            raise SU.CHBSimError(
                self.simstate,
                iaddr,
                "Address " + str(address) + " not found in memory")
        elif self._mem[offset].is_link():
            if self.bigendian:
                return self.get_symbolic_big_endian(iaddr, offset, size)
            else:
                return self.get_symbolic_little_endian(iaddr, offset, size)
        elif size == 1:
            return self.get_byte(iaddr, offset)
        if self.bigendian:
            return self.get_big_endian(iaddr, offset, size)
        else:
            return self.get_little_endian(iaddr, offset, size)

    def get_link_byte(self, iaddr: str, offset: int) -> SimMemoryByteLink:
        if offset in self._mem:
            simbyte = self._mem[offset]
            if simbyte.is_link():
                return cast(SimMemoryByteLink, simbyte)
            else:
                raise UF.CHBError(
                    iaddr + ": Byte at " + hex(offset) + " is not a link byte")
        else:
            raise UF.CHBError(
                iaddr + ": No byte found at offset " + hex(offset))

    def get_symbolic_big_endian(
            self, iaddr: str, offset: int, size: int) -> SSV.SimSymbolicValue:
        if size == 2:
            b1 = self.get_link_byte(iaddr, offset + 1)
            b2 = self.get_link_byte(iaddr, offset)
            if (
                    b1.linkedto is b2.linkedto
                    and b1.position == 0 and b2.position == 1
                    and b1.linkedto.size == 2):
                return b1.linkedto
            else:
                raise UF.CHBError(
                    "Error in retrieving symbolic word value from memory: "
                    + hex(offset))
        elif size == 4:
            b1 = self.get_link_byte(iaddr, offset + 3)
            b2 = self.get_link_byte(iaddr, offset + 2)
            b3 = self.get_link_byte(iaddr, offset + 1)
            b4 = self.get_link_byte(iaddr, offset)
            if (
                    b1.linkedto is b2.linkedto
                    and b1.linkedto is b3.linkedto
                    and b1.linkedto is b4.linkedto
                    and b1.linkedto.size == 4):
                return b1.linkedto
            else:
                raise UF.CHBError(
                    "Error in retrieving symbolic doubleword value from memory: "
                    + hex(offset))
        else:
            raise UF.CHBError(
                "Size " + str(size) + " not supported for symbolic memory values.")

    def get_symbolic_little_endian(
            self, iaddr: str, offset: int, size: int) -> SSV.SimSymbolicValue:
        if size == 2:
            b1 = self.get_link_byte(iaddr, offset)
            b2 = self.get_link_byte(iaddr, offset + 1)
            if (
                    b1.linkedto is b2.linkedto
                    and b1.position == 0 and b2.position == 1
                    and b1.linkedto.size == 2):
                return b1.linkedto
            else:
                raise UF.CHBError(
                    "Error in retrieving symbolic word value from memory: "
                    + hex(offset))
        elif size == 4:
            b1 = self.get_link_byte(iaddr, offset)
            b2 = self.get_link_byte(iaddr, offset + 1)
            b3 = self.get_link_byte(iaddr, offset + 2)
            b4 = self.get_link_byte(iaddr, offset + 3)
            if (
                    b1.linkedto is b2.linkedto
                    and b1.linkedto is b3.linkedto
                    and b1.linkedto is b4.linkedto
                    and b1.linkedto.size == 4):
                return b1.linkedto
            else:
                raise UF.CHBError(
                    "Error in retrieving symbolic doubleword value from memory: "
                    + hex(offset))
        else:
            raise UF.CHBError(
                "Size " + str(size) + " not supported for symbolic memory values.")

    def get_little_endian(
            self, iaddr: str, offset: int, size: int) -> SV.SimLiteralValue:
        if size == 2:
            b1 = self.get_byte(iaddr, offset)
            b2 = self.get_byte(iaddr, offset + 1)
            return SV.compose_simvalue([b1, b2])
        elif size == 4:
            b1 = self.get_byte(iaddr, offset)
            b2 = self.get_byte(iaddr, offset + 1)
            b3 = self.get_byte(iaddr, offset + 2)
            b4 = self.get_byte(iaddr, offset + 3)
            return SV.compose_simvalue([b1, b2, b3, b4])
        else:
            raise SU.CHBSimError(
                self.simstate,
                iaddr,
                "Size of memory value request not supported: " + str(size))

    def get_big_endian(
            self, iaddr: str, offset: int, size: int) -> SV.SimLiteralValue:
        if size == 2:
            b1 = self.get_byte(iaddr, offset + 1)
            b2 = self.get_byte(iaddr, offset)
            return SV.compose_simvalue([b1, b2])
        elif size == 4:
            b1 = self.get_byte(iaddr, offset + 3)
            b2 = self.get_byte(iaddr, offset + 2)
            b3 = self.get_byte(iaddr, offset + 1)
            b4 = self.get_byte(iaddr, offset)
            return SV.compose_simvalue([b1, b2, b3, b4])
        else:
            raise SU.CHBSimError(
                self.simstate,
                iaddr,
                ("Size of memory value request not supported: "
                 + str(size)))

    def get_char_string(
            self, iaddr: str, address: SSV.SimAddress, size: int) -> str:
        offset = address.offsetvalue
        if offset not in self._mem:
            raise SU.CHBSimError(
                self.simstate,
                iaddr,
                "Address " + str(address) + " not found in memory")
        if self._mem[offset].is_link():
            return "----"
        if size == 4:
            b1 = self.get_byte(iaddr, offset + 3)
            b2 = self.get_byte(iaddr, offset + 2)
            b3 = self.get_byte(iaddr, offset + 1)
            b4 = self.get_byte(iaddr, offset)
            result = ""
            if b1.value == 0 and b2.value == 0 and b3.value == 0 and b4.value == 0:
                return result
            if self.bigendian:
                seq = [b4, b3, b2, b1]
            else:
                seq = [b1, b2, b3, b4]
            for b in seq:
                if b.value > 10 and b.value < 127:
                    result += chr(b.value)
                else:
                    result += "?"
            return result
        else:
            return "?"

    def to_byte_string(self) -> str:
        if len(self._mem) > 0:
            s = ""
            for a in range(self.lowaddr, self.highaddr+1):
                if a in self._mem:
                    if self._mem[a].is_link():
                        byte = 0
                    else:
                        byte = self._mem[a].value
                else:
                    byte = 0
                b = '{0:#0{1}x}'.format(byte, 4)[2:]
                s += b
            n = 80
            stringlist = [s[i: i + n] for i in range(0, len(s), n)]
            return "\n".join(stringlist)
        else:
            return ""

    def mk_address(self, offset: int) -> SSV.SimAddress:
        addr = cast(SV.SimDoubleWordValue, SV.mk_simvalue(offset, size=4))
        if self.name == "global":
            return SSV.SimGlobalAddress(addr)
        elif self.name == "stack":
            return SSV.SimStackAddress(addr)
        else:
            return SSV.SimBaseAddress(self.name, addr)

    def __str__(self) -> str:
        lines: List[str] = []
        if self.size > 0:
            if self.lowaddr < 0:
                lowaddr = ((self.lowaddr // 4) - 1) * 4
            else:
                lowaddr = (self.lowaddr // 4) * 4
            highaddr = self.highaddr
            for a in range(lowaddr, highaddr, 4):
                try:
                    if a in self._mem:
                        address = self.mk_address(a)
                        try:
                            charstring = self.get_char_string("", address, 4)
                        except UF.CHBError:
                            charstring = "?"
                        lines.append(str(hex(a)).rjust(12)
                                     + '  ' + str(a).rjust(12)
                                     + '  ' + str(self.get("0", address, 4))
                                     + '  ' + str(charstring))
                except SU.CHBSimValueUndefinedError:
                    lines.append(str(hex(a)).rjust(12) + "  ?")
                except SU.CHBSimError:
                    lines.append(str(hex(a)).rjust(12) + "  ?")

        return "\n".join(lines)


class SimGlobalMemory(SimMemory):

    def __init__(self, simstate: "SimulationState") -> None:
        SimMemory.__init__(self, simstate, True, "global")


class SimStackMemory(SimMemory):

    def __init__(self, simstate: "SimulationState") -> None:
        SimMemory.__init__(self, simstate, False, "stack")
