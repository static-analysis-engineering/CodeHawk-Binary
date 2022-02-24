# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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
"""Represents memory segments that are identified by a base address.

The most common case is the heap, where a memory segment has an unknown symbolic
base, and distinct segments are guaranteed not to overlap. BaseMemory, however,
may also be used initially for pointers passed in to functions, of which it is
not yet known at what kind of memory they point.
"""

from typing import Optional, TYPE_CHECKING

from chb.simulation.SimMemory import SimMemory
import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.simulation.SimulationState import SimulationState


class SimBaseMemory(SimMemory):

    def __init__(
            self,
            simstate: "SimulationState",
            base: str,
            initialized: bool = False,
            buffersize: Optional[int] = None) -> None:
        SimMemory.__init__(self, simstate, initialized, base)
        self._buffersize = buffersize
        self._status = "valid"

    @property
    def simstate(self) -> "SimulationState":
        return self._simstate

    @property
    def bigendian(self) -> bool:
        return self.simstate.bigendian

    @property
    def buffersize(self) -> int:
        if self._buffersize is not None:
            return self._buffersize
        else:
            raise UF.CHBError("Buffersize of memory is not known")

    def free(self) -> None:
        self._status = "freed"

    def is_valid(self) -> bool:
        return self._status == "valid"

    def has_buffersize(self) -> bool:
        return self.buffersize is not None

    def get(self,
            iaddr: str,
            address: SSV.SimAddress,
            size: int) -> SV.SimValue:
        try:
            memval = SimMemory.get(self, iaddr, address, size)
        except SU.CHBSimError as e:
            print("Error in basemem: " + str(e))
            name = (self.name
                    + '['
                    + str(address.offsetvalue)
                    + ']'
                    + ' (value not retrieved: '
                    + str(e)
                    + ')')
            return SSV.SimSymbol(name)
        else:
            return memval
