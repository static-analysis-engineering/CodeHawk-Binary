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
"""Top-level state representation of a simulation run.

A simulation run includes one top-level state that represents all shared entities,
such as stack, heap, and registers, and substates for the main executable (can
be a library) and (optionally) for each of the dynamically linked libraries that
contains static global memory, visible only to the submodule. Dynamically
linked libraries can be optionally included; alternatively, library functions
may be stubbed out. Global addresses include the name of the module in which
address space they are mapped. Each submodule has its own resolution of linked
library functions.
"""

from abc import ABC, abstractmethod
from typing import (
    cast, Dict, List, Mapping, Optional, Sequence, TYPE_CHECKING, Union)

from chb.app.Operand import Operand

from chb.simulation.ELFSimGlobalMemory import ELFSimGlobalMemory
from chb.simulation.SimBaseMemory import SimBaseMemory, SimStringMemory

import chb.simulation.SimFileUtil as SFU

from chb.simulation.SimLocation import (
    SimLocation, SimRegister, SimMemoryLocation)
from chb.simulation.SimMappedMemory import SimMappedMemory
from chb.simulation.SimProgramCounter import SimProgramCounter
from chb.simulation.SimSharedMemory import SimSharedMemory

from chb.simulation.SimMemory import SimMemory, SimStackMemory
from chb.simulation.SimStub import SimStub
from chb.simulation.SimSupport import SimSupport
import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV
import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.elfformat.ELFSection import ELFSymbolTable


prefer_stubs = [
    "access",
    "atoi",
    "calloc",
    "cdbg_printf",
    "chdir",
    "close",
    "exit",
    "fclose",
    "fcntl",
    "fflush",
    "fgets",
    "fileno",
    "fopen",
    "fork",
    "fprintf",
    "fputc",
    "fputs",
    "free",
    "fscanf",
    "fwrite",
    "get_current_dir_name",
    "getenv",
    "getopt_long",
    "gmtime",
    "inet_addr",
    "inet_aton",
    "ioctl",
    "malloc",
    "mallopt",
    "memcpy",
    "memset",
    "mmap",
    "open",
    "printf",
    "putenv",
    "realloc",
    "remove",
    "rename",
    "setsid",
    "shmat",
    "shmget",
    "sigaction",
    "sleep",
    "snprintf",
    "socket",
    "sprintf",
    "stat",
    "strcasecmp",
    "strcat",
    "strcmp",
    "strcpy",
    "strftime",
    "strlcpy",
    "strlen",
    "strncasecmp",
    "strncpy",
    "strstr",
    "strtok",
    "system",
    "tcsetattr",
    "time",
    "unlink",
    "unsetenv",
    "write"]


class SimModule:

    def __init__(
            self,
            name: str,
            app: "AppAccess",
            base: str,
            max_addr: str,
            loadaddr: str = None) -> None:
        self._name = name
        self._app = app
        self._base = base  # base address in hex
        self._imports: Dict[int, str] = {}
        self._exports: Dict[str, int] = {}
        self._max_addr = max_addr
        self._loadaddr = loadaddr

    @property
    def name(self) -> str:
        return self._name

    @property
    def app(self) -> "AppAccess":
        return self._app

    @property
    def base(self) -> str:
        """Return base address in hex."""

        return self._base

    @property
    def base_i(self) -> int:
        """Return base address as integer."""

        return int(self.base, 16)

    @property
    def max_addr(self) -> str:
        """Return maximum address in adress space."""

        return self._max_addr

    @property
    def max_addr_i(self) -> int:
        return int(self.max_addr, 16)

    @property
    def loadaddr(self) -> str:
        """Return address where module is loaded."""

        return self._loadaddr

    def has_load_address(self) -> bool:
        return self.loadaddr is not None

    @property
    def loadaddr_i(self) -> int:
        if self.has_load_address():
            return int(self.loadaddr, 16)
        else:
            return 0

    @property
    def imports(self) -> Dict[int, str]:
        if len(self._imports) == 0:
            libstubs = self.app.functionsdata.library_stubs()
            for (x, s) in libstubs.items():
                self._imports[int(x, 16)] = s
        return self._imports

    @property
    def exports(self) -> Dict[str, int]:
        if len(self._exports) == 0:
            symtab = cast("ELFSymbolTable", self.app.header.get_dynamic_symbol_table())
            for (sid, sym) in symtab.symbols.items():
                if sym.is_exported:
                    self._exports[sym.st_name] = int(sym.value, 16)

                    # sometimes symbols are available only with prefix __libc_
                    if sym.st_name.startswith("__libc_"):
                        self._exports[sym.st_name[7:]] = int(sym.value, 16)
        return self._exports

    def is_imported(self, addr: int) -> bool:
        return addr in self.imports

    def is_exported(self, sym: str) -> bool:
        if sym in prefer_stubs:
            return False
        else:
            return sym in self.exports

    def import_symbol(self, addr: int) -> str:
        if self.is_imported(addr):
            return self.imports[addr]
        else:
            raise UF.CHBError(
                "Address " + hex(addr) + " not found in imports of " + self.name)

    def export_address(self, sym: str) -> int:
        if self.is_exported(sym):
            print(
                "Symbol "
                + sym
                + " linked to "
                + self.name
                + ":"
                + hex(self.exports[sym]))
            return self.exports[sym]
        else:
            raise UF.CHBError(
                "Symbol " + sym + " not found in exports of " + self.name)

    def has_function_name(self, addr: int):
        return self.app.has_function_name(hex(addr))

    def has_function(self, addr: int):
        return self.app.has_function(hex(addr))

    def function_name(self, addr: int):
        if self.has_function_name(addr):
            return self.app.function_name(hex(addr))
        else:
            raise UF.CHBError(
                "No function name associated with " + hex(addr))

    def has_address(self, addr: int) -> bool:
        return (addr >= self.base_i and addr <= self.max_addr_i)

    def has_address_as_loaded(self, addr: int) -> bool:
        """Return true if there is a load address and address is in that range."""

        if self.has_load_address():
            modaddr = addr - self.loadaddr_i
            return self.has_address(modaddr)
        else:
            return False

    def get_address_in_module(self, addr: int) -> int:
        """Return address as contained in executable module address space."""

        if self.has_load_address():
            return addr - self.loadaddr_i
        else:
            raise UF.CHBError("Module has no load address: " + self.name)


class ModuleSimulationState:

    def __init__(
            self,
            simstate: "SimulationState",
            module: SimModule) -> None:
        self._module = module
        self._simstate = simstate
        self._globalmem = ELFSimGlobalMemory(self, self.module.app.header)

    @property
    def module(self) -> SimModule:
        return self._module

    @property
    def modulename(self) -> str:
        return self.module.name

    @property
    def simstate(self) -> "SimulationState":
        return self._simstate

    @property
    def globalmem(self) -> ELFSimGlobalMemory:
        return self._globalmem

    def is_literal_address(self, iaddr: str, addrvalue: int) -> bool:
        return addrvalue > self.module.base_i

    def resolve_literal_address(
            self, iaddr: str, addrvalue: int) -> SSV.SimGlobalAddress:
        if self.module.has_address(addrvalue):
            return SSV.mk_global_address(addrvalue, modulename=self.modulename)
        elif self.module.has_address_as_loaded(addrvalue):
            modaddrvalue = self.module.get_address_in_module(addrvalue)
            return SSV.mk_global_address(modaddrvalue, modulename=self.modulename)
        else:
            return SSV.mk_undefined_global_address(self.modulename)

    def set_memval(
            self,
            iaddr: str,
            address: SSV.SimGlobalAddress,
            srcval: SV.SimValue) -> None:
        self.globalmem.set(iaddr, address, srcval)

    def memval(
            self,
            iaddr: str,
            address: SSV.SimGlobalAddress,
            size: int,
            signextend: bool = False) -> SV.SimValue:
        return self.globalmem.get(iaddr, address, size)


class TraversalEdge:

    def __init__(self, src: str, callsite: str, dst: str) -> None:
        self._src = src
        self._callsite = callsite
        self._dst = dst
        self._traversals: int = 0

    @property
    def src(self) -> str:
        return self._src

    @property
    def callsite(self) -> str:
        return self._callsite

    @property
    def dst(self) -> str:
        return self._dst

    @property
    def traversals(self) -> int:
        return self._traversals

    def traverse(self) -> None:
        self._traversals += 1

    def __str__(self) -> str:
        return (
            "  "
            + self.src.ljust(8)
            + "  "
            + self.callsite.ljust(8)
            + "  "
            + self.dst.ljust(8)
            + "  "
            + str(self.traversals).rjust(4))


class SimulationInitializer:

    def __init__(self) -> None:
        pass

    def do_initialization(self, simstate: "SimulationState") -> None:
        pass


class SimulationDataDisplay:

    def __init__(self) -> None:
        pass

    def display_registers(self, simstate: "SimulationState") -> str:
        return "none"


class SimulationTrace:

    def __init__(self) -> None:
        self._trace: List[str] = []
        self._delayed_trace: List[str] = []
        self._traversaledges: Dict[str, Dict[str, Dict[str, TraversalEdge]]] = {}
        self._appcalls: List[str] = []

    @property
    def trace(self) -> List[str]:
        return self._trace

    @property
    def delayed_trace(self) -> List[str]:
        return self._delayed_trace

    def reset_delayed_trace(self) -> None:
        self._delayed_trace = []

    def add(self, s: str) -> None:
        self._trace.append(s)

    def add_delayed(self, s: str) -> None:
        self._delayed_trace.append(s)

    def include_delayed(self) -> None:
        if len(self.delayed_trace) > 0:
            self._trace.extend(self.delayed_trace)
            self.reset_delayed_trace()

    def add_appcall(self, s: str) -> None:
        self._appcalls.append(s)

    @property
    def traversaledges(self) -> Dict[str, Dict[str, Dict[str, TraversalEdge]]]:
        return self._traversaledges

    def traverse_edge(self, src: str, callsite: str, dst: str) -> None:
        self.traversaledges.setdefault(src, {})
        self.traversaledges[src].setdefault(callsite, {})
        self.traversaledges[src][callsite].setdefault(dst, TraversalEdge(src, callsite, dst))
        self.traversaledges[src][callsite][dst].traverse()

    def traversals(self) -> str:
        lines: List[str] = []
        for src in sorted(self.traversaledges):
            for callsite in sorted(self.traversaledges[src]):
                for dst in sorted(self.traversaledges[src][callsite]):
                    lines.append(str(self.traversaledges[src][callsite][dst]))
        return "\n".join(lines)

    def __str__(self) -> str:
        return ("\n".join(self.trace)
                + "\n\nTraversals\n"
                + self.traversals()
                + "\n\nApplication calls\n"
                + "\n".join("   " + a for a in self._appcalls))


class SimulationState:

    def __init__(
            self,
            startaddr: str,
            mainx: SimModule,
            simprogramcounter: SimProgramCounter,
            siminitializer: SimulationInitializer = SimulationInitializer(),
            simsupport: SimSupport = SimSupport(),
            simdatadisplay: SimulationDataDisplay = SimulationDataDisplay(),
            dynlibs: Sequence[SimModule] = [],
            stubs: Mapping[str, SimStub] = {},
            bigendian: bool = False) -> None:
        self._startaddr = startaddr
        self._mainx = mainx
        self._simprogramcounter = simprogramcounter
        self._siminitializer = siminitializer
        self._dynlibs = dynlibs
        self._simsupport = simsupport
        self._simdatadisplay = simdatadisplay
        self._stubs = stubs
        self._bigendian = bigendian

        # module states
        self._modulestates: Dict[str, ModuleSimulationState] = {}

        # registers and memory (registers are assumed to be 32 bits wide)
        self.registers: Dict[str, SV.SimValue] = {}
        self.stackmem = SimStackMemory(self)
        self.basemem: Dict[str, SimBaseMemory] = {}
        self.mappedmem: Dict[str, SimMappedMemory] = {}
        self.sharedmem: Dict[int, SimSharedMemory] = {}  # indexed by id returned by shmget

        # log
        self.fnlog: Dict[str, List[str]] = {}

        # trace
        self._trace = SimulationTrace()

        # initialization
        self.siminitializer.do_initialization(self)
        self.simsupport.do_initialization(self)

    @property
    def startaddr(self) -> str:
        return self._startaddr

    @property
    def mainx(self) -> SimModule:
        return self._mainx

    @property
    def siminitializer(self) -> SimulationInitializer:
        return self._siminitializer

    @property
    def simsupport(self) -> SimSupport:
        return self._simsupport

    @property
    def simdatadisplay(self) -> SimulationDataDisplay:
        return self._simdatadisplay

    @property
    def dynlibs(self) -> Sequence[SimModule]:
        """Return dynamically linked libraries that are included in the simulation."""

        return self._dynlibs

    @property
    def stubs(self) -> Mapping[str, SimStub]:
        return self._stubs

    @property
    def bigendian(self) -> bool:
        return self._bigendian

    @property
    def modulestates(self) -> Dict[str, ModuleSimulationState]:
        if len(self._modulestates) == 0:
            self._modulestates[self.mainx.name] = ModuleSimulationState(self, self.mainx)
            for d in self.dynlibs:
                self._modulestates[d.name] = ModuleSimulationState(self, d)
        return self._modulestates

    @property
    def trace(self) -> SimulationTrace:
        return self._trace

    # --- program counter ---

    @property
    def simprogramcounter(self) -> SimProgramCounter:
        return self._simprogramcounter

    @property
    def programcounter(self) -> SSV.SimGlobalAddress:
        return self.simprogramcounter.programcounter

    @property
    def modulename(self) -> str:
        return self.simprogramcounter.modulename

    @property
    def modulestate(self) -> ModuleSimulationState:
        return self.modulestates[self.modulename]

    @property
    def module(self) -> SimModule:
        return self.modulestate.module

    @property
    def function_address(self) -> str:
        """Return the hex address of the current function."""

        return self.simprogramcounter.function_address

    def set_function_address(self, faddr: str) -> None:
        self.simprogramcounter.set_function_address(faddr)

    def set_programcounter(self, pc: SSV.SimGlobalAddress) -> None:
        self.simprogramcounter.set_programcounter(pc)

    def increment_programcounter(self) -> None:
        self.simprogramcounter.increment_programcounter(self)

    # --- import symbol resolution ---

    def resolve_import_symbol(self, importsym: str) -> SSV.SimGlobalAddress:
        for dynlib in self.dynlibs:
            if dynlib.is_exported(importsym):
                faddr = dynlib.export_address(importsym)
                return SSV.mk_global_address(faddr, dynlib.name)
        else:
            return SSV.mk_undefined_global_address(self.modulename)

    def is_import_symbol_stubbed(self, importsym: str) -> bool:
        return False

    def has_stub(self, name: str) -> bool:
        return name in self.stubs

    def stub_functioncall(self, iaddr: str, name: str) -> None:
        if name in self.stubs:
            if self.simsupport.has_call_intercept(name):
                intercept = self.simsupport.call_intercept(name)
                intercept.do_before(iaddr, self)
            returnaddr = self.simprogramcounter.returnaddress(iaddr, self)
            stub = self.stubs[name]
            msg = stub.simulate(iaddr, self)
            self.trace.add(" ".ljust(15) + iaddr + "   " + msg)
            self.simprogramcounter.set_programcounter(returnaddr)
        else:
            raise SU.CHBSimError(self, iaddr, "Missing stub: " + name)

    # --- simulation values ---

    def set(
            self,
            iaddr: str,
            dstop: Operand,
            srcval: SV.SimValue) -> SimLocation:
        size = dstop.size
        if srcval.is_literal and (not srcval.is_defined):
            self.add_logmsg(iaddr, "Assigning undefined value to " + str(dstop))
        lhs = self.lhs(iaddr, dstop)
        if lhs.is_register:
            lhs = cast(SimRegister, lhs)
            self.set_register(iaddr, lhs.register, srcval)
        elif lhs.is_memory_location:
            lhs = cast(SimMemoryLocation, lhs)
            self.set_memval(iaddr, lhs.simaddress, srcval)
        else:
            raise SU.CHBSimError(self, iaddr, "lhs not recognized: " + str(lhs))
        return lhs

    def rhs(self, iaddr: str, op: Operand, opsize: int = 4) -> SV.SimValue:
        if op.is_register:
            return self.regval(iaddr, op.register, opsize=opsize)
        elif op.is_immediate:
            return SV.mk_simvalue(op.value, size=opsize)
        elif op.is_indirect_register:
            regval = self.regval(iaddr, op.indirect_register)
            offset = op.offset
            if not regval.is_defined:
                return SV.mk_undefined_simvalue(opsize)
            if regval.is_string_address and opsize == 1:
                regval = cast(SSV.SimStringAddress, regval)
                return self.rhs_string_char(iaddr, regval, offset)
            if regval.is_symbol:
                regval = cast(SSV.SimSymbol, regval)
                return self.rhs_symbol(iaddr, regval, offset, opsize)
            elif regval.is_address:
                regval = cast(SSV.SimAddress, regval)
                return self.memval(iaddr, regval.add_offset(offset), opsize)
            elif regval.is_literal:
                regval = cast(SV.SimLiteralValue, regval)
                return self.rhs_literal_address(iaddr, regval.value, offset, opsize)
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    "Unable to resolve indirect register operand: " + str(op))
        else:
            raise SU.CHBSimError(
                self, iaddr, "Operand " + str(op) + " not recognized in rhs")

    def rhs_string_char(
            self, iaddr: str, addr: SSV.SimStringAddress, offset: int) -> SV.SimValue:
        regstr = addr.stringval
        if offset == len(regstr):
            return SV.simZerobyte
        elif offset < len(regstr):
            return SV.mk_simbytevalue(ord(regstr[offset]))
        else:
            raise SU.CHBSimError(
                self,
                iaddr,
                ("Access of string value out of bounds. String: "
                 + regstr
                 + "; offset: "
                 + str(offset)))

    def rhs_symbol(
            self,
            iaddr: str,
            sym: SSV.SimSymbol,
            offset: int,
            opsize: int) -> SV.SimValue:
        base = sym.name
        if base.startswith("/stderr"):
            return sym
        if base not in self.basemem:
            self.basemem[base] = SimBaseMemory(self, base)
            self.add_logmsg(iaddr, "Initialize base memory for " + base)
        addr: SSV.SimAddress = SSV.mk_base_address(base, offset=offset)
        return self.memval(iaddr, addr, opsize)

    def rhs_literal_address(
            self,
            iaddr: str,
            addrvalue: int,
            offset: int,
            opsize: int) -> SV.SimValue:
        addr = self.resolve_literal_address(iaddr, addrvalue)
        return self.memval(iaddr, addr.add_offset(offset), opsize)

    def get_string_from_memaddr(self, iaddr: str, saddr: SSV.SimAddress) -> str:
        result = ""
        offset = 0
        while True:
            srcaddr = saddr.add_offset(offset)
            srcval = self.memval(iaddr, srcaddr, 1)
            if srcval.is_defined and srcval.is_literal:
                srcval = cast(SV.SimLiteralValue, srcval)
                if srcval.value == 0:
                    break
                else:
                    result += chr(srcval.value)
                    offset += 1
            else:
                break
        return result

    # --- locations ---

    def compute_indirect_address(self, iaddr: str, op: Operand) -> SSV.SimAddress:
        regval = self.regval(iaddr, op.indirect_register)
        if regval.is_address:
            regval = cast(SSV.SimAddress, regval)
            return regval.add_offset(op.offset)
        elif regval.is_literal:
            return self.resolve_literal_address(iaddr, regval.literal_value + op.offset)
        else:
            raise UF.CHBError("Indirect address cannot be resolved: " + str(op))

    def resolve_literal_address(
            self, iaddr: str,
            addrvalue: int) -> SSV.SimGlobalAddress:
        if self.modulename in self.modulestates:
            addr = self.modulestates[self.modulename].resolve_literal_address(
                iaddr, addrvalue)
        else:
            addr = SSV.mk_undefined_global_address(self.modulename)

        if addr.is_defined:
            return addr

        else:
            for shmid in self.sharedmem:
                if self.sharedmem[shmid].has_address(addrvalue):
                    addr = SSV.mk_global_address(addrvalue, "shared:" + str(shmid))
                    return addr

            else:
                for m in self.modulestates:
                    addr = self.modulestates[m].resolve_literal_address(
                        iaddr, addrvalue)
                    if addr.is_defined:
                        return addr
                else:
                    raise SU.CHBSimAddressError(
                        self,
                        iaddr,
                        hex(addrvalue),
                        self.modulename,
                        ("Unable to resolve address: "
                         + hex(addrvalue)
                         + " in "
                         + self.modulename))

    def lhs(self, iaddr: str, op: Operand) -> SimLocation:
        if op.is_register:
            return SimRegister(op.register)
        '''
        elif (
                op.is_indirect_register
                and self.regval(iaddr, op.indirect_register).is_string_address):
            saddr = cast(SSV.SimStringAddress, self.regval(iaddr, op.indirect_register))
            return SimStringPosition(saddr, op.offset) '''
        if op.is_indirect_register:
            addr = self.compute_indirect_address(iaddr, op)
            return SimMemoryLocation(addr)
        elif op.is_immediate:
            addr = self.resolve_literal_address(iaddr, op.value)
            return SimMemoryLocation(addr)
        else:
            raise SU.CHBSimError(
                self, iaddr, "Unable to determine location for " + str(op))

    # --- registers ---

    def set_register(self, iaddr: str, reg: str, srcval: SV.SimValue) -> None:
        self.registers[reg] = srcval

    def regval(self, iaddr: str, reg: str, opsize: int = 4) -> SV.SimValue:
        if reg in self.registers:
            v = self.registers[reg]
            if opsize == 4:
                return v
            elif opsize == 1:
                if v.is_literal and v.is_defined:
                    v = cast(SV.SimDoubleWordValue, v)
                    return v.simbyte1
                else:
                    return SV.simUndefinedByte
            elif opsize == 2:
                if v.is_literal and v.is_defined:
                    v = cast(SV.SimDoubleWordValue, v)
                    return v.lowword
                else:
                    return SV.simUndefinedWord
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    "regval with opsize: "
                    + str(opsize)
                    + " not recognized")
        else:
            self.add_logmsg(iaddr, "no value for register: " + reg)
            return SV.mk_undefined_simvalue(opsize)

    # --- memory ---

    def set_memval(
            self,
            iaddr: str,
            address: SSV.SimAddress,
            srcval: SV.SimValue) -> None:
        try:
            if address.is_global_address:
                address = cast(SSV.SimGlobalAddress, address)
                name = address.modulename
                if name in self.modulestates:
                    self.modulestates[name].set_memval(iaddr, address, srcval)
                elif name.startswith("shared"):
                    shmid = int(name[7:])
                    if shmid in self.sharedmem:
                        self.sharedmem[shmid].set(iaddr, address, srcval)
                    else:
                        raise SU.CHBSimError(
                            self,
                            iaddr,
                            ("Shared memory with identifier "
                             + str(shmid)
                             + " not found"))
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        ("Module name not recognized: "
                         + name
                         + " ("
                         + ", ".join(name for name in self.modulestates)
                         + ")"))
            elif address.is_stack_address:
                self.stackmem.set(iaddr, address, srcval)
            elif address.is_string_address:
                address = cast(SSV.SimStringAddress, address)
                base = address.base
                if base not in self.basemem:
                    self.basemem[base] = SimStringMemory(
                        self, base, address.stringval)
                    self.add_logmsg(iaddr, "initialize string memory for " + base)
                self.basemem[base].set(iaddr, address, srcval)
            elif address.is_base_address:
                address = cast(SSV.SimBaseAddress, address)
                base = address.base
                if base not in self.basemem:
                    self.basemem[base] = SimBaseMemory(
                        self, base, buffersize=address.buffersize)
                    self.add_logmsg(iaddr, "initialize base memory for " + base)
                self.basemem[base].set(iaddr, address, srcval)
            else:
                raise SU.CHBSimError(
                    self, iaddr, "Address not recognized: " + str(address))
        except SU.CHBSimError as e:
            self.add_logmsg(iaddr, "error in set_memval: " + str(e))
            raise SU.CHBSimError(
                self, iaddr, "set_memval: " + str(address) + ": " + str(e))

    def memval(
            self,
            iaddr: str,
            address: SSV.SimAddress,
            size: int,
            signextend: bool = False) -> SV.SimValue:
        try:
            if address.is_global_address:
                address = cast(SSV.SimGlobalAddress, address)
                name = address.modulename
                if name in self.modulestates:
                    return self.modulestates[name].memval(iaddr, address, size)
                elif name.startswith("shared:"):
                    shmid = int(name[7:])
                    if shmid in self.sharedmem:
                        return self.sharedmem[shmid].get(iaddr, address, size)
                    else:
                        raise SU.CHBSimError(
                            self,
                            iaddr,
                            ("Shared memory with identifier "
                             + str(shmid)
                             + " not found"))
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        ("Module name not recognized: "
                         + name
                         + " ("
                         + ", ".join(name for name in self.modulestates)
                         + ")"))
            elif address.is_stack_address:
                return self.stackmem.get(iaddr, address, size)
            elif address.is_string_address:
                address = cast(SSV.SimStringAddress, address)
                base = address.base
                if address.base not in self.basemem:
                    self.basemem[base] = SimStringMemory(
                        self, base, address.stringval)
                    self.add_logmsg(iaddr, "initialize string memory for " + base)
                return self.basemem[base].get(iaddr, address, size)
            elif address.is_base_address:
                address = cast(SSV.SimBaseAddress, address)
                if address.base in self.basemem:
                    return self.basemem[address.base].get(iaddr, address, size)
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        ("Base of base address: "
                         + address.base
                         + " not found in state's basemem"))
            else:
                raise SU.CHBSimError(
                    self, iaddr, "Address not recognized: " + str(address))
        except SU.CHBSimError as e:
            self.add_logmsg(
                iaddr,
                ("no value for memory address: "
                 + str(address)
                 + " ("
                 + str(e)
                 + ")"))
            return SV.mk_undefined_simvalue(size)

    # --- logging ---

    def add_logmsg(self, key: str, msg: str) -> None:
        self.fnlog.setdefault(key, [])
        self.fnlog[key].append(msg)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("")
        lines.append(str(self.simprogramcounter))
        lines.append("")

        # registers
        lines.append(self.simdatadisplay.display_registers(self))
        lines.append("")

        # stack
        lines.append("-" * 80)
        lines.append("Stack memory:")
        lines.append("-" * 80)
        lines.append(str(self.stackmem))
        lines.append("=" * 80)
        lines.append("")

        # heap
        lines.append("-" * 80)
        lines.append("Heap memory:")
        lines.append("-" * 80)
        for base in self.basemem:
            lines.append("Base: " + base)
            lines.append("-" * 80)
            lines.append(str(self.basemem[base]))
            lines.append("~" * 80)
        lines.append("=" * 80)
        lines.append("")

        # log messages
        if self.fnlog:
            lines.append('-' * 80)
            lines.append('Log messages:')
            lines.append('-' * 80)
            for a in sorted(self.fnlog):
                lines.append('  ' + str(a) + ' (' + str(len(self.fnlog[a])) + ')')
                for x in self.fnlog[a]:
                    lines.append('    ' + str(x))
            lines.append('=' * 80)

        return "\n".join(lines)
