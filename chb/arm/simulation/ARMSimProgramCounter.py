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

from typing import TYPE_CHECKING, Union

from chb.simulation.SimProgramCounter import SimProgramCounter
import chb.simulation.SimSymbolicValue as SSV

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.simulation.SimulationState import SimulationState


class ARMSimProgramCounter(SimProgramCounter):

    def __init__(self, pc: SSV.SimGlobalAddress) -> None:
        self._programcounter = pc
        self._functionaddr = hex(pc.offsetvalue)

    @property
    def programcounter(self) -> SSV.SimGlobalAddress:
        return self._programcounter

    @property
    def modulename(self) -> str:
        return self.programcounter.modulename

    @property
    def function_address(self) -> str:
        return self._functionaddr

    def returnaddress(
            self, iaddr: str, simstate: "SimulationState") -> SSV.SimGlobalAddress:
        raise UF.CHBError("Not implemented yet")

    def set_function_address(self, faddr: str) -> None:
        self._functionaddr = faddr

    def set_programcounter(self, pc: SSV.SimGlobalAddress) -> None:
        self._programcounter = pc

    def set_delayed_programcounter(
            self, pc: Union[SSV.SimGlobalAddress, SSV.SimDynamicLinkSymbol]) -> None:
        raise UF.CHBError("Not applicable to ARM")

    def increment_programcounter(self, simstate: "SimulationState") -> None:
        self.set_programcounter(self.programcounter.add_offset(4))
