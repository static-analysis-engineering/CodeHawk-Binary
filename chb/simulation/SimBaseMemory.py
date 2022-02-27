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

from typing import cast, Optional, TYPE_CHECKING

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


class SimStringMemory(SimBaseMemory):
    """Represents the unknown memory that holds a constant string.

    It allows for modification of the memory to reflect that not all programs
    respect the restriction. Violations are logged.
    """

    def __init__(
            self,
            simstate: "SimulationState",
            base: str,
            strvalue: str) -> None:
        SimBaseMemory.__init__(
            self, simstate, base, initialized=True, buffersize=len(strvalue) + 1)
        self._strvalue = strvalue    # original string value
        self._strval: Optional[str] = strvalue
        self._initialize()

    @property
    def base(self) -> str:
        return self.name

    @property
    def original_string(self) -> str:
        return self._strvalue

    def has_stringval(self) -> bool:
        return self._strval is not None

    @property
    def stringval(self) -> str:
        if self._strval is not None:
            return self._strval
        else:
            raise UF.CHBError(
                "SimString Memory value unknown for "
                + self.original_string
                + " in "
                + self.base)

    def free(self) -> None:
        self.simstate.add_logmsg(
            "stringmem:" + self.base,
            "illegal free of constant string: " + self.original_string)

    def is_modified(self) -> bool:
        return (
            (not self.has_stringval())
            or (self.original_string != self.stringval))

    def get(self, iaddr: str, address: SSV.SimAddress, size: int) -> SV.SimValue:
        offset = address.offsetvalue
        if self.has_stringval() and offset < self.buffersize-1 and size == 1:
            return SV.mk_simvalue(ord(self.stringval[offset]), size=1)
        elif self.has_stringval() and offset == self.buffersize-1 and size == 1:
            return SV.simZerobyte
        else:
            return SimBaseMemory.get(self, iaddr, address, size)

    def set(
            self,
            iaddr: str,
            address: SSV.SimAddress,
            srcval: SV.SimValue) -> None:
        """Modify the string if this is a one-char replacement."""

        offset = address.offsetvalue
        self.simstate.add_logmsg(
            "stringmem:" + self.base + "@" + iaddr,
            "modifying constant string: " + self.original_string)
        if (
                srcval.is_literal
                and srcval.size == 1
                and self._strval is not None):
            newchar = chr(cast(SV.SimLiteralValue, srcval).value)
            if offset <= len(self.stringval):
                self._strval = (
                    self._strval[:offset] + newchar + self._strval[offset + 1:])
                SimBaseMemory.set(self, iaddr, address, srcval)
                self._strval = None
            else:
                self.simstate.add_logmsg(
                    "stringmem:" + self.base + "@" + iaddr,
                    "attempt to write beyond the limits of a constant string")
        else:
            SimBaseMemory.set(self, iaddr, address, srcval)
            self._strval = None

    def _initialize(self) -> None:
        for (offset, c) in enumerate(self.original_string):
            charval = SV.mk_simvalue(ord(c), size=1)
            address = SSV.mk_base_address(
                self.base, offset=offset, buffersize=self.buffersize)
            SimBaseMemory.set(self, "0x0", address, charval)
        ntaddress = SSV.mk_base_address(
            self.base, offset=self.buffersize-1, buffersize=self.buffersize)
        SimBaseMemory.set(self, "0x0", ntaddress, SV.simZerobyte)
