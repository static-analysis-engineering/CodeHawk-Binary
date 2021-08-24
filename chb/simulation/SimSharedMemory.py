# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
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
"""Represents a shared memory segment created by shmget.

From: https://pubs.opengroup.org/onlinepubs/9699919799/

int shmget(key_t key, size_t size, int shmflg);

The shmget() function shall return the shared memory identifier associated with key.

A share memory identifier, associate data structure, and share memory segment of
at least size bytes are created for key if one of the following is true:
- The argument key is equal to IPC_PRIVATE ( (key_t) 0).
- The argument key does not already have a shared memory identifier associated with
  it and (shmflg & IPC_CREAT) is non_zero (#define IPC_CREAT 0001000)

Upon successfull completion, shmget() shall return a non-negative integer, a shared-
memory identifier.

"""

from typing import Dict, List, Optional, TYPE_CHECKING

from chb.simulation.SimMemory import SimMemory
import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.simulation.SimulationState import SimulationState


class SimSharedMemory(SimMemory):

    def __init__(
            self,
            simstate: "SimulationState",
            shmid: int,
            key: str,   # hex value
            buffersize: int = 4096) -> None:
        SimMemory.__init__(self, simstate, True, "shared:" + str(shmid))
        self._shmid = shmid
        self._buffersize = buffersize
        # segments may be mapped in multiple locations
        self._baseoffsets: List[int] = []

    @property
    def simstate(self) -> "SimulationState":
        return self._simstate

    @property
    def shmid(self) -> int:
        return self._shmid

    @property
    def bigendian(self) -> bool:
        return self.simstate.bigendian

    @property
    def has_offset(self) -> bool:
        return len(self._baseoffsets) > 0

    @property
    def baseoffsets(self) -> List[int]:
        return self._baseoffsets

    def set_baseoffset(self, offset: int) -> None:
        self._baseoffsets.append(offset)

    @property
    def buffersize(self) -> int:
        return self._buffersize

    def has_address(self, addr: int) -> bool:
        for offset in self.baseoffsets:
            if addr >= offset and addr < offset + self.buffersize:
                return True
        else:
            return False

    def initialize(self, iaddr: str):
        addr = SSV.mk_global_address(0, "shared")
        for i in range(0, self.buffersize):
            SimMemory.set(self, iaddr, addr.add_offset(i), SV.simZerobyte)

    def set(self,
            iaddr: str,
            address: SSV.SimAddress,
            srcval: SV.SimValue) -> None:
        for base in self.baseoffsets:
            if (
                    address.offsetvalue >= base
                    and address.offsetvalue < base + self.buffersize):
                address = address.add_offset(-base)
                SimMemory.set(self, iaddr, address, srcval)
                break
        else:
            raise SU.CHBSimError(
                self.simstate, iaddr, "Invalid shared memory address: " + str(address))

    def get(self,
            iaddr: str,
            address: SSV.SimAddress,
            size: int) -> SV.SimValue:
        try:
            for base in self.baseoffsets:
                if (
                        address.offsetvalue >= base
                        and address.offsetvalue < base + self.buffersize):
                    address = address.add_offset(-base)
                    try:
                        memval = SimMemory.get(self, iaddr, address, size)
                    except SU.CHBSimError:
                        memval = SV.mk_simvalue(0, size=size)
                    return memval
            else:
                raise SU.CHBSimError(
                    self.simstate,
                    iaddr,
                    "invalid shared memory address: " + str(address))
        except SU.CHBSimError as e:
            print("Error in shared memory: " + str(e))
            name = (self.name
                    + '['
                    + str(address.offsetvalue)
                    + ']'
                    + ' (value not retrieved: '
                    + str(e)
                    + ')')
            return SSV.SimSymbol(name)

    def __str__(self) -> str:
        lines: List[str] = []
        if self.has_offset:
            try:
                for a in range(0, self.buffersize, 4):
                    if a in self._mem:
                        address = self.mk_address(a)
                        try:
                            charstring = self.char_string("", address, 4)
                        except UF.CHBError:
                            charstring = "?"
                        memval = SimMemory.get(self, "0", address, 4)
                        lines.append(str(hex(a)).rjust(12)
                                     + "  " + str(a).rjust(12)
                                     + "  " + str(memval)
                                     + "  " + str(charstring))
            except Exception:
                pass
        return "\n".join(lines)
