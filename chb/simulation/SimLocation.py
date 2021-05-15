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

from typing import TYPE_CHECKING

import chb.util.fileutil as UF

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV


class SimLocation:

    def __init__(self) -> None:
        pass

    def is_register(self) -> bool:
        return False

    def is_double_register(self) -> bool:
        return False

    def is_memory_location(self) -> bool:
        return False

    def is_global(self) -> bool:
        return False

    def is_aligned(self) -> bool:
        return False

    def __str__(self) -> str:
        return "location"


class SimRegister(SimLocation):

    def __init__(self, reg: str) -> None:
        self.reg = reg

    def is_register(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.reg


class SimDoubleRegister(SimLocation):

    def __init__(self, reglow: str, reghigh: str) -> None:
        self.reglow = reglow
        self.reghigh = reghigh

    def is_double_register(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.reglow + ':' + self.reghigh


class SimMemoryLocation(SimLocation):

    def __init__(self, simaddress: SSV.SimAddress) -> None:
        self._simaddress = simaddress

    @property
    def simaddress(self) -> SSV.SimAddress:
        return self._simaddress

    def is_memory_location(self) -> bool:
        return True

    def is_aligned(self) -> bool:
        return self.simaddress.is_aligned()

    def is_global(self) -> bool:
        return self.simaddress.is_global_address()

    def is_stack(self) -> bool:
        return self.simaddress.is_stack_address()

    @property
    def offset(self) -> SV.SimDoubleWordValue:
        if self.is_stack():
            return self.simaddress.offset
        else:
            raise UF.CHBError('Location is not a stack location: ' + str(self))

    @property
    def address(self) -> int:
        if self.is_global():
            return self.simaddress.offsetvalue
        else:
            raise UF.CHBError("Memory Location does not have an address: "
                              + str(self))

    def __str__(self) -> str:
        return str(self.simaddress)
