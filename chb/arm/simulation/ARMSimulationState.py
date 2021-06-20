# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
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

from typing import (
    Callable, cast, Dict, List, Mapping, Optional, Sequence, Tuple, TYPE_CHECKING)

from chb.simulation.SimLocation import (SimLocation, SimRegister, SimMemoryLocation)
from chb.simulation.SimMemory import SimMemory
from chb.simulation.SimulationState import SimulationState

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV
import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.arm.ARMAccess import ARMAccess


class ARMSimulationState(SimulationState):

    def __init__(
            self,
            app: "ARMAccess",
            basename: str,
            imagebase: str,
            startaddr: str,
            bigendian: bool = False) -> None:
        SimulationState.__init__(self, bigendian)
        self.app = app
        self.basename = basename

        self._imagebase = SSV.mk_global_address(int(imagebase, 16))
        self._programcounter: SV.SimValue = SSV.mk_global_address(int(startaddr, 16))

    @property
    def imagebase(self) -> SSV.SimGlobalAddress:
        return self._imagebase

    @property
    def programcounter(self) -> SSV.SimGlobalAddress:
        return cast(SSV.SimGlobalAddress, self._programcounter)

    def set_programcounter(self, pc: SV.SimValue) -> None:
        if pc.is_address:
            pc = cast(SSV.SimAddress, pc)
            if pc.is_global_address:
                self._programcounter = pc
            else:
                raise SU.CHBSimError(
                    self,
                    str(self._programcounter),
                    "New pc is not a global address: " + str(pc))
        else:
            raise SU.CHBSimError(
                self,
                str(self._programcounter),
                "New pc is not an address: " + str(pc))

    def increment_program_counter(self) -> None:
        self.set_programcounter(self.programcounter.add_offset(4))
