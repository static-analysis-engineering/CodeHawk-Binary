# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyrigth (c) 2021      Aarno Labs LLC
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


import chb.simulation.SimValue as SV


class SimBaseValue(SV.SimValue):
    """Symbolic base plus offset.

    A SimBaseValue has a partial value. It consists of a symbolic base and
    a one-, or two-bytes offset that can be subjected to arithmetic and
    bitwise operations. A SimBaseValue, in contrast with a SimBaseAddress,
    is not an address. A SimBaseValue maye be the result of some (generally
    disallowed) operations on addresses. Examples are the result of complementing
    a stack address to extract alignment information.
    """

    def __init__(
            self,
            base: str,
            value: int,
            bytecount: int = 2,
            defined: bool = True):
        SV.SimValue.__init__(self, defined=defined)
        self._base = base
        self._bytecount = bytecount
        if bytecount == 1:
            self._value = value & 255
        else:
            self._value = value & 65535
            self._byte1 = self.value & 255
            self._byte2 = self.value >> 8

    @property
    def width(self) -> int:
        return 32

    @property
    def size(self) -> int:
        return 4

    @property
    def value(self) -> int:
        return self._value

    @property
    def base(self) -> str:
        return self._base

    def bitwise_and(self, other: SV.SimLiteralValue) -> SV.SimValue:
        if other.is_literal():
            if other.value < self.value:
                newval = self.value & other.value
                return SV.mk_simvalue(newval)
            else:
                return mk_simbasevalue('unknown', self.value & other.value)
        else:
            return SV.simUndefinedDW

    def __str__(self) -> str:
        return '[[' + self.base + ']]:' + str(self.value)


def mk_simbasevalue(base: str, value: int) -> SimBaseValue:
    return SimBaseValue(base, value)
