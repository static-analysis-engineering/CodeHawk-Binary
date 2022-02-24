# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
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

from typing import List, TYPE_CHECKING

from chb.simulation.SimulationState import SimulationInitializer
import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV

if TYPE_CHECKING:
    from chb.simulation.SimulationState import SimulationState


class MIPSimInitializer(SimulationInitializer):

    def __init__(
            self,
            cmdlineargs: List[str] = []) -> None:
        self._cmdlineargs = cmdlineargs

    @property
    def cmdlineargs(self) -> List[str]:
        return self._cmdlineargs

    def do_initialization(self, simstate: "SimulationState") -> None:
        simstate.registers["sp"] = SSV.SimStackAddress(SV.simZero)
        simstate.registers["zero"] = SV.simZero
        for reg in [
                "ra", "gp", "fp", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"]:
            simstate.registers[reg] = SSV.SimSymbol(reg + "_in")
        simstate.registers["t9"] = SSV.mk_global_address(
            int(simstate.startaddr, 16), modulename=simstate.modulename)

        if len(self.cmdlineargs) > 0:
            self.initialize_cmdline_arguments(simstate)

    def initialize_cmdline_arguments(self, simstate: "SimulationState") -> None:
        simstate.registers["a0"] = SV.mk_simvalue(len(self.cmdlineargs))
        simstate.registers["a1"] = SSV.mk_stack_address(16)

        aoffset = 100  # offset of information block on the initial process stack
        for (i, arg) in enumerate(self.cmdlineargs):
            argptr = SSV.mk_stack_address((i * 4) + 16)
            argvalptr = SSV.mk_stack_address(aoffset)
            simstate.set_memval(simstate.startaddr, argptr, argvalptr)
            for c in arg:
                addr = SSV.mk_stack_address(aoffset)
                cval = SV.mk_simcharvalue(c)
                simstate.set_memval(simstate.startaddr, addr, cval)
                aoffset += 1
            addr = SSV.mk_stack_address(aoffset)
            simstate.set_memval(simstate.startaddr, addr, SV.simZerobyte)
            aoffset += 1

        # null-terminate the list of arguments
        argptr = SSV.mk_stack_address((len(self.cmdlineargs) * 4) + 16)
        simstate.set_memval(simstate.startaddr, argptr, SV.simZero)
