# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2020 Henny Sipma
# Copyright (c) 2021 Aarno Labs LLC
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

from chb.simulation.SimLocation import SimRegister, SimMemoryLocation
from chb.simulation.SimSymbolicValue import SimAddress

import chb.util.fileutil as UF


class MIPSimRegister(SimRegister):

    def __init__(self, reg: str) -> None:
        SimRegister.__init__(self, reg)


class MIPSimMemoryLocation(SimMemoryLocation):

    def __init__(self, simaddress: SimAddress) -> None:
        SimMemoryLocation.__init__(self, simaddress)

    def is_base_location(self) -> bool:
        return self.simaddress.is_base_address()

    def __str__(self) -> str:
        if self.is_stack():
            return "stack[" + str(self.simaddress.offsetvalue) + "]"
        elif self.is_global():
            return "global[" + str(self.simaddress.offsetvalue) + "]"
        elif self.is_base_location():
            return self.simaddress.base + "[" + str(self.simaddress.offsetvalue) + "]"
        else:
            return str("loc@" + str(self.simaddress))
