# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022      Aarno Labs LLC
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
"""Class for managing the program counter in a mips simulation.

In MIPS management of the program counter is somewhat complicated by the presence
of a delayslot in the architecture, which may cause instructions to be executed
out of order.

The method increment_programcounter handles this by maintaining a delayed program
counter, that is executed one cycle after it has been emitted by the instruction.
"""

from typing import cast, List, Optional, TYPE_CHECKING, Union

from chb.simulation.SimProgramCounter import SimProgramCounter

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.simulation.SimulationState import SimulationState


class MIPSimProgramCounter(SimProgramCounter):

    def __init__(self, pc: SSV.SimGlobalAddress) -> None:
        self._programcounter = pc
        self._delayed_programcounter: Optional[
            Union[SSV.SimGlobalAddress, SSV.SimDynamicLinkSymbol]] = None
        self._functionaddr = hex(pc.offsetvalue)

    @property
    def programcounter(self) -> SSV.SimGlobalAddress:
        return self._programcounter

    def set_programcounter(self, addr: SSV.SimGlobalAddress) -> None:
        self._programcounter = addr

    def has_delayed_programcounter(self) -> bool:
        return self._delayed_programcounter is not None

    @property
    def delayed_programcounter(self) -> Union[SSV.SimGlobalAddress, SSV.SimDynamicLinkSymbol]:
        if self._delayed_programcounter is not None:
            return self._delayed_programcounter
        else:
            raise UF.CHBError("Delayed programcounter is not set")

    def set_delayed_programcounter(
            self,
            address: Union[SSV.SimGlobalAddress, SSV.SimDynamicLinkSymbol]) -> None:
        self._delayed_programcounter = address

    def reset_delayed_programcounter(self) -> None:
        self._delayed_programcounter = None

    @property
    def modulename(self) -> str:
        return self.programcounter.modulename

    @property
    def function_address(self) -> str:
        return self._functionaddr

    def set_function_address(self, addr: str) -> None:
        self._functionaddr = addr

    def returnaddress(
            self, iaddr: str, simstate: "SimulationState") -> SSV.SimGlobalAddress:
        simra = simstate.regval(iaddr, "ra")

        if simra.is_undefined:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "return address is undefined")

        if simra.is_global_address:
            return cast(SSV.SimGlobalAddress, simra)

        elif simra.is_literal:
            g = simstate.resolve_literal_address(iaddr, simra.literal_value)
            if g.is_defined:
                return g

            else:
                raise SU.CHBSimError(
                    simstate,
                    iaddr,
                    "return address cannot be resolved: " + str(simra))
        else:
            raise SU.CHBSimError(
                simstate,
                iaddr,
                "return address value not recognized: " + str(simra))

    def increment_programcounter(self, simstate: "SimulationState") -> None:
        if self.has_delayed_programcounter():
            self.handle_delayed_programcounter(simstate)
        else:
            self.set_programcounter(self.programcounter.add_offset(4))

    def handle_delayed_programcounter(self, simstate: "SimulationState") -> None:
        iaddr = hex(self.programcounter.offsetvalue - 4)
        if self.delayed_programcounter.is_dynamic_link_symbol:
            linksymbol = cast(SSV.SimDynamicLinkSymbol, self.delayed_programcounter)
            tgtaddr = linksymbol.address
            self.transfer_to_linked_function(
                simstate, iaddr, tgtaddr, linksymbol.name)

        else:
            delayed_programcounter = cast(
                SSV.SimGlobalAddress, self.delayed_programcounter)
            addrval = delayed_programcounter.offsetvalue

            if simstate.modulename == "external":
                self.set_programcounter(delayed_programcounter)

            elif simstate.module.is_imported(addrval):
                importsym = simstate.module.import_symbol(addrval)
                exportaddr = simstate.resolve_import_symbol(importsym)
                if exportaddr.is_defined:
                    self.transfer_to_exported_function(
                        simstate, iaddr, importsym, exportaddr)
                elif importsym in simstate.stubs:
                    simstate.stub_functioncall(iaddr, importsym)
                else:
                    raise SU.CHBSimError(
                        simstate,
                        iaddr,
                        ("Unable to determine location of imported value: "
                         + hex(addrval)
                         + "("
                         + importsym
                         + ") in module "
                         + self.modulename))

            elif simstate.module.has_function_name(addrval):
                fname = simstate.module.function_name(addrval)
                if fname in simstate.stubs:
                    simstate.stub_functioncall(iaddr, fname)
                else:
                    self.transfer_to_app_function(simstate, iaddr, fname)

            elif simstate.module.has_function(addrval):
                self.transfer_to_app_function(simstate, iaddr, hex(addrval))

            else:
                # delay slot created by branch
                self.set_programcounter(delayed_programcounter)

        self.reset_delayed_programcounter()

    def transfer_to_exported_function(
            self,
            simstate: "SimulationState",
            iaddr: str,
            importsym: str,
            exportaddr: SSV.SimGlobalAddress) -> None:
        simstate.trace.add_delayed(
            "\nEntering function "
            + importsym
            + " ("
            + str(exportaddr)
            + ")")
        if simstate.simsupport.has_call_intercept(importsym):
            intercept = simstate.simsupport.call_intercept(importsym)
            intercept.do_before(iaddr, simstate)
        simstate.set_register(iaddr, "t9", exportaddr)
        self.set_programcounter(exportaddr)
        simstate.set_function_address(hex(exportaddr.offsetvalue))
        simstate.trace.traverse_edge(self.function_address, iaddr, importsym)

    def transfer_to_app_function(
            self, simstate: "SimulationState", iaddr: str, name: str) -> None:
        delayed_programcounter = cast(SSV.SimGlobalAddress, self.delayed_programcounter)
        simstate.trace.add_delayed("\nEntering function " + name)
        if simstate.simsupport.has_call_intercept(name):
            intercept = simstate.simsupport.call_intercept(name)
            intercept.do_before(iaddr, simstate)
        simstate.set_register(iaddr, "t9", delayed_programcounter)
        self.set_programcounter(delayed_programcounter)
        simstate.trace.traverse_edge(
            self.function_address, iaddr, hex(delayed_programcounter.offsetvalue))
        simstate.set_function_address(hex(delayed_programcounter.offsetvalue))

    def transfer_to_linked_function(
            self,
            simstate: "SimulationState",
            iaddr: str,
            tgtaddr: SSV.SimGlobalAddress,
            name: str) -> None:
        simstate.trace.add_delayed("\nEntering runtime-linked function " + name)
        simstate.set_register(iaddr, "t9", tgtaddr)
        self.set_programcounter(tgtaddr)
        simstate.trace.traverse_edge(self.function_address, iaddr, name)
        simstate.set_function_address(hex(tgtaddr.offsetvalue))

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("\nProgram counter: " + str(self.programcounter))
        lines.append("-" * 80)
        return "\n".join(lines)
