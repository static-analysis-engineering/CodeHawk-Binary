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

from chb.mips.MIPSOperand import MIPSOperand

from chb.mips.simulation.MIPSimSupport import MIPSimSupport
from chb.mips.simulation.MIPSimLocation import (
    MIPSimMemoryLocation, MIPSimRegister)

from chb.mips.simulation.MIPSimMemory import (
    MIPSimGlobalMemory, MIPSimStackMemory, MIPSimBaseMemory)

from chb.mips.simulation.MIPSimStubs import MIPSimStub, stubbed_libc_functions

from chb.simulation.SimLocation import (SimLocation, SimRegister, SimMemoryLocation)
from chb.simulation.SimMemory import SimMemory
from chb.simulation.SimulationState import SimulationState

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV
import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.mips.MIPSAccess import MIPSAccess
    from chb.mips.MIPSFunction import MIPSFunction


class FunctionContext:
    """Keeps track of the function call stack.

    Note: this may be imprecise due to missed returns or returns that span
    multiple invocations.
    """

    def __init__(
            self, simstate: "MIPSimulationState") -> None:
        self._simstate = simstate
        self._functions: List[str] = []
        self.callback_returnaddress: Optional[SV.SimValue] = None
        self.currentmipsfn: Optional["MIPSFunction"] = None

    @property
    def simstate(self) -> "MIPSimulationState":
        return self._simstate

    @property
    def app(self) -> "MIPSAccess":
        return self.simstate.app

    @property
    def addressref(self) -> Mapping[str, Tuple[str, List[str]]]:
        """Allows retrieval of functions, given an instruction and block address.

        structure: iaddr -> (baddr, [ faddr ]), all hex.
        """

        return self.app.address_reference()

    def functions(self) -> List[str]:
        return self._functions

    def is_empty(self) -> bool:
        return len(self.functions()) == 0

    def get_context_string(self) -> str:
        return ":".join(f[-4:] for f in self.functions())

    def get_addr_reffn(self, iaddr: str) -> Optional[Tuple[str, str]]:
        if iaddr in self.addressref:
            (baddr, fns) = self.addressref[iaddr]
            if len(fns) == 1:
                return (baddr, fns[0])
            elif len(fns) == 0:
                self.simstate.add_logmsg(iaddr, "addrreffn: no functions found")
            else:
                self.simstate.add_logmsg(
                    iaddr,
                    "addrreffn: multiple functions found: " + ','.join(fns))
        return None

    def get_loop_nesting(self, iaddr: str) -> Optional[Sequence[str]]:
        if iaddr in self.addressref:
            addrrefn = self.get_addr_reffn(iaddr)   # (baddr,faddr)
            if addrrefn:
                if self.currentmipsfn and self.currentmipsfn.faddr == addrrefn[1]:
                    return self.currentmipsfn.cfg.loop_levels(addrrefn[0])
                elif self.currentmipsfn is None:
                    self.simstate.add_logmsg(
                        iaddr, 'mips function has not been set')
                else:
                    self.simstate.add_logmsg(
                        iaddr,
                        ('reffn: ' + addrrefn[1] + '; contextfn: '
                         + str(self.currentmipsfn.faddr)
                         + ' (all: ' + ','.join(self.functions()) + ')'))
            else:
                self.simstate.add_logmsg(
                    iaddr, "address reference has not been set")
        return None

    def push(self, faddr: str) -> None:
        self.functions().append(faddr)
        if self.app.has_function(faddr):
            self.currentmipsfn = self.app.function(faddr)

    def pop(self, programcounter: str = "0", iaddr: str = "0") -> str:
        if self.is_empty():
            return "nothing to pop"
        else:
            returnfrom = self.functions().pop()
            addrreffn = self.get_addr_reffn(programcounter)    # (baddr,faddr)
            if self.functions and addrreffn:
                ctxtfn = self.peek()
                if addrreffn[1] == ctxtfn:
                    if self.app.has_function(ctxtfn):
                        self.currentmipsfn = self.app.function(ctxtfn)
                    else:
                        self.simstate.add_logmsg(
                            iaddr, 'no function found for ' + ctxtfn)
                else:
                    return self.pop(programcounter)
            else:
                self.currentmipsfn = None
            return returnfrom

    def peek(self) -> str:
        if self.is_empty():
            return "none"
        else:
            return self.functions()[-1]

    def restore(self, faddr: str) -> None:
        while self.peek() != faddr:
            self.pop()

    def __str__(self) -> str:
        return ', '.join(self.functions())


class MIPSimulationState(SimulationState):

    def __init__(self,
                 app: "MIPSAccess",
                 basename: str,      # name of executable
                 imagebase: str,     # base address of the image (hex)
                 startaddr: str,     # address to start simulation (hex)
                 bigendian: bool = False,
                 # support class with custom initialization and stubs
                 simsupport: MIPSimSupport = MIPSimSupport('0x0'),
                 baseaddress: int = 0,  # load address, to be added to imagebase
                 # library to statically include functions from
                 libapp: Optional["MIPSAccess"] = None,
                 # target executable for dynamic loading
                 xapp: Optional["MIPSAccess"] = None) -> None:
        SimulationState.__init__(self, bigendian)
        self.app = app
        self.basename = basename
        self.baseaddress = baseaddress
        self.simsupport = simsupport

        # context
        self._imagebase = SSV.mk_global_address(int(imagebase, 16))
        self.context = FunctionContext(self)
        self._programcounter: SV.SimValue = SSV.mk_global_address(int(startaddr, 16))
        self.delayed_programcounter: Optional[SSV.SimSymbolicValue] = None

        # registers and memory
        self.registers: Dict[str, SV.SimValue] = {}      # register name -> SimValue
        self.registers['zero'] = SV.SimDoubleWordValue(0)
        self.stackmem = MIPSimStackMemory(self)
        self.globalmem = MIPSimGlobalMemory(self, self.app.header)
        self.basemem: Dict[str, MIPSimBaseMemory] = {}

        # static library (optional)
        self.libapp = libapp
        if self.libapp is not None:
            self.libstubs: Dict[int, Tuple[str, Optional[MIPSimStub]]] = {}
            self.libglobalmem = MIPSimGlobalMemory(self, self.libapp.header)
            # function-name -> function address in static lib
            self.static_lib: Dict[str, str] = {}
            libimgbase = self.libapp.header.image_base
            self.libimagebase = SSV.SimGlobalAddress(SV.SimDoubleWordValue(
                int(libimgbase, 16)))

        self.instaticlib = False

        # target executable for dynamic loading (optional)
        self.xapp = xapp
        if self.xapp is not None:
            self.xglobalmem = MIPSimGlobalMemory(self, self.xapp.header)

        # log
        self.fnlog: Dict[str, List[str]] = {}  # iaddr -> msg list2

        # environment
        self.environment: Dict[str, str] = {}   # string -> string
        # string -> string ; non-volatile ram default values
        self.nvram: Dict[str, str] = {}
        # string -> f() -> string
        self.network_input: Dict[str, Callable[[], str]] = {}

        # library/application function stubs

        # int (int-address) -> (name,stub)
        self.stubs: Dict[int, Tuple[str, Optional[MIPSimStub]]] = {}
        # int (int-address) -> (name,stub)
        self.appstubs: Dict[int, Tuple[str, MIPSimStub]] = {}
        # name -> stub ; dynamically linked symbols
        self.dlstubs: Dict[str, MIPSimStub] = {}

        # libc functions implemented by tables
        self.ctype_toupper: Optional[int] = None
        self.ctype_b: Optional[int] = None

        self._initialize()
        self.function_start_initialization()
        self.push_context(startaddr)

    @property
    def imagebase(self) -> SSV.SimGlobalAddress:
        return self._imagebase

    def function_start_initialization(self) -> None:
        self.registers['sp'] = SSV.SimStackAddress(SV.simZero)   # stackpointer
        for reg in [
                'ra', 'gp', 'fp', 's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7']:
            self.registers[reg] = SSV.SimSymbol(reg + '_in')
        self.simsupport.do_initialization(self)

    # --- context ---

    def push_context(self, faddr: str) -> None:
        self.context.push(faddr)

    def pop_context(self, programcounter: str) -> str:
        return self.context.pop(programcounter)

    def restore_context(self, faddr: str) -> None:
        self.context.restore(faddr)

    # --- stubs ---

    def get_function_stub(self, addrvalue: int) -> MIPSimStub:
        if addrvalue in self.stubs:
            stub = self.stubs[addrvalue][1]
            if stub is not None:
                return stub
            else:
                raise UF.CHBError("No stub found for " + hex(addrvalue))
        elif addrvalue in self.appstubs:
            return self.appstubs[addrvalue][1]
        else:
            raise UF.CHBError('No stub found for addr: ' + hex(addrvalue))

    def is_libc_ctype_toupper(self, iaddr: int) -> bool:
        return iaddr == self.ctype_toupper

    def is_libc_ctype_b(self, iaddr: int) -> bool:
        return iaddr == self.ctype_b

    def set_dlsym_stub(self, iaddr: str, name: str) -> None:
        if name in stubbed_libc_functions:
            self.dlstubs[name] = stubbed_libc_functions[name](self.app)
            self.add_logmsg(iaddr, 'dlsym:' + name + ' added')
            return
        else:
            customstubs = self.simsupport.get_lib_stubs()
            if name in customstubs:
                self.dlstubs[name] = customstubs[name](self.app)
                self.add_logmsg(iaddr, 'dlsym:' + name + ' added')
                return
        self.add_logmsg(iaddr, 'dlsym:' + name + ' not found')

    # --- statically included library ---

    def set_in_static_lib(self, v: bool) -> None:
        self.instaticlib = v

    def set_static_lib(self, libfns: Dict[str, str]) -> None:
        for name in libfns:
            self.static_lib[name] = libfns[name]

    def get_lib_function_stub(self, addrvalue: int) -> MIPSimStub:
        stub = self.libstubs[addrvalue][1]
        if stub is not None:
            return stub
        else:
            raise UF.CHBError("No library stub found for " + hex(addrvalue))

    # --- environment / nvram ---

    def has_environment_variable(self, name: str) -> bool:
        return name in self.environment

    def get_environment_variable_value(self, name: str) -> str:
        if self.has_environment_variable(name):
            return self.environment[name]
        else:
            raise UF.CHBError(
                'Value for environment variable ' + name + ' not found')

    def set_environment_variable(self, name: str, value: str) -> None:
        self.environment[name] = value

    def set_environment(self, d: Dict[str, str]) -> None:
        for key in d:
            self.environment[key] = d[key]

    def set_nvram(self, d: Dict[str, str]) -> None:
        for key in d:
            self.nvram[key] = d[key]

    # --- network input ---

    def set_network_input(self, iaddr: str, f: Callable[[], str]) -> None:
        self.network_input[iaddr] = f

    def get_network_input(self, iaddr: str) -> Callable[[], str]:
        if self.has_network_input(iaddr):
            return self.network_input[iaddr]
        else:
            raise UF.CHBError('No network input found for address ' + iaddr)

    def has_network_input(self, iaddr: str) -> bool:
        return iaddr in self.network_input

    # --- program counter ---

    def set_delayed_program_counter(self, address: SSV.SimSymbolicValue) -> None:
        if address.is_global_address:
            address = cast(SSV.SimGlobalAddress, address)
            self.delayed_programcounter = address

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
        if self.delayed_programcounter:
            if self.delayed_programcounter.is_dynamic_link_symbol:
                dpc = cast(SSV.SimDynamicLinkSymbol, self.delayed_programcounter)
                iaddr = hex(self.programcounter.offsetvalue - 4)
                dlsym = dpc.name
                if dlsym in self.dlstubs:
                    msg = self.dlstubs[dlsym].simulate(iaddr, self)
                    print('     dlsym: ' + msg)
                    self.set_programcounter(self.get_regval(iaddr, 'ra'))
                    self.delayed_programcounter = None
                else:
                    print('Missing dlsym stub: ' + dlsym)
                    exit(1)
            elif self.delayed_programcounter.is_symbol:
                self.set_programcounter(self.delayed_programcounter)
                self.delayed_programcounter = None
            elif self.delayed_programcounter.is_global_address:
                dpcg = cast(SSV.SimGlobalAddress, self.delayed_programcounter)
                iaddr = hex(self.programcounter.offsetvalue - 4)
                addrvalue = dpcg.offsetvalue
                if self.libapp and hex(addrvalue) in self.static_lib:
                    raise SU.CHBSimStaticLibFunction(
                        iaddr, self.static_lib[hex(addrvalue)], self.registers)
                if addrvalue in self.stubs:
                    if self.stubs[addrvalue][1]:
                        returnaddr = self.get_regval(hex(addrvalue), 'ra')
                        try:
                            msg = self.get_function_stub(
                                addrvalue).simulate(iaddr, self)
                            print('     ' + hex(addrvalue) + ': ' + msg)
                            self.set_programcounter(returnaddr)
                            self.delayed_programcounter = None
                        except SU.CHBSimCallbackException as e:
                            print('     ' + hex(addrvalue) + ': ' + e.msg)
                            print('     ---> callback to ' + str(e.pc))
                            self.set_programcounter(e.pc)
                            self.delayed_programcounter = None
                            self.context.callback_returnaddress = returnaddr
                            # self.push_context(e.pc.to_hex())
                        except SU.CHBSimPopContextException as e:
                            print('     ' + hex(addrvalue) + ': ' + e.msg)
                            print('     ----> pop context: ' + str(
                                self.pop_context(hex(addrvalue))))
                            self.set_programcounter(returnaddr)
                            self.delayed_programcounter = None
                    else:
                        print('Missing stub: ' + self.stubs[addrvalue][0])
                        exit(1)
                elif addrvalue in self.appstubs:
                    msg = self.get_function_stub(addrvalue).simulate(iaddr, self)
                    print('    ' + hex(addrvalue) + ': ' + msg)
                    self.set_programcounter(self.get_regval(hex(addrvalue), 'ra'))
                    self.delayed_programcounter = None
                elif self.libapp and self.instaticlib and addrvalue in self.libstubs:
                    if self.libstubs[addrvalue][1]:
                        msg = self.get_lib_function_stub(
                            addrvalue).simulate(iaddr, self)
                        print('    ' + hex(addrvalue) + ': ' + msg)
                        if 'longjmp' not in msg:
                            self.set_programcounter(
                                self.get_regval(hex(addrvalue), 'ra'))
                        self.delayed_programcounter = None
                    else:
                        print('Missing stub: ' + self.libstubs[addrvalue][0])
                        exit(1)
                else:
                    self.set_programcounter(self.delayed_programcounter)
                    self.delayed_programcounter = None
            else:
                self.set_programcounter(self.delayed_programcounter)
                self.add_logmsg(
                    str(self.delayed_programcounter),
                    'instruction pointer is not a global memory address')
        else:
            self.set_programcounter(self.programcounter.add_offset(4))

    # --- registers and memory ---

    def set_register(self, iaddr: str, reg: str, srcval: SV.SimValue) -> None:
        self.registers[reg] = srcval

    def set(
            self,
            iaddr: str,
            dstop: MIPSOperand,
            srcval: SV.SimValue) -> SimLocation:
        size = dstop.size
        if srcval.is_literal and (not srcval.is_defined):
            self.add_logmsg(iaddr, 'Source value is undefined: ' + str(dstop))
        lhs = self.get_lhs(iaddr, dstop)
        if lhs.is_register:
            lhs = cast(SimRegister, lhs)
            self.set_register(iaddr, lhs.register, srcval)
        elif lhs.is_memory_location:
            lhs = cast(SimMemoryLocation, lhs)
            self.set_memval(iaddr, lhs.simaddress, srcval)
        else:
            raise SU.CHBSimError(self, iaddr, 'lhs not recognized: ' + str(lhs))
        return lhs

    def get_rhs(self, iaddr: str, op: MIPSOperand, opsize: int = 4) -> SV.SimValue:
        opkind = op.opkind
        if opkind.is_mips_register or opkind.is_mips_special_register:
            reg = opkind.register
            return self.get_regval(iaddr, reg, opsize)
        elif opkind.is_mips_immediate:
            return SV.mk_simvalue(opsize, opkind.value)
        elif opkind.is_mips_indirect_register:
            reg = opkind.register
            offset = opkind.offset
            regval = self.get_regval(iaddr, reg)
            if not regval.is_defined:
                return SV.mk_undefined_simvalue(opsize)
            if regval.is_string_address and opsize == 1:
                regval = cast(SSV.SimStringAddress, regval)
                regstring = regval.stringval
                if offset == len(regstring):
                    return SV.SimByteValue(0)
                elif offset > len(regstring):
                    print('Accessing string value out of bounds')
                    exit(1)
                else:
                    return SV.mk_simvalue(ord(regval.stringval[offset]), size=1)
            if regval.is_symbol:
                regval = cast(SSV.SimSymbol, regval)
                base = regval.name
                if base not in self.basemem:
                    self.basemem[base] = MIPSimBaseMemory(self, base)
                address: SSV.SimAddress = SSV.mk_base_address(base, offset=offset)
                return self.get_memval(iaddr, address, opsize)
            elif regval.is_address:
                regval = cast(SSV.SimAddress, regval)
                address = regval.add_offset(offset)
                return self.get_memval(iaddr, address, opsize)
            elif regval.is_literal and self.instaticlib:
                regval = cast(SV.SimLiteralValue, regval)
                if regval.value > self.libimagebase.offsetvalue:
                    address = SSV.mk_global_address(regval.value + offset)
                    return self.get_memval(iaddr, address, opsize)
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        ("Register value in static lib not recognized: "
                         + str(regval)))
            elif regval.is_literal:
                regval = cast(SV.SimLiteralValue, regval)
                if regval.value > self.imagebase.offsetvalue:
                    address = SSV.mk_global_address(regval.value + offset)
                    return self.get_memval(iaddr, address, opsize)
                elif regval.value <= self.imagebase.offsetvalue:
                    print('Invalid address: ' + str(regval))
                    return SV.mk_undefined_simvalue(opsize)
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        "Register value not recognized: " + str(regval))

            elif regval.is_string_address:
                regval = cast(SSV.SimStringAddress, regval)
                if offset < len(regval.stringval):
                    return SV.mk_simvalue(ord(regval.stringval[0]), size=opsize)
                elif offset == len(regval.stringval):
                    return SV.mk_simvalue(0, size=opsize)   # null terminator
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        ('string address: '
                         + regval.stringval
                         + ' with offset: '
                         + str(offset)))

            elif regval.is_libc_table_address:
                regval = cast(SSV.SimLibcTableAddress, regval)
                return SSV.mk_libc_table_value(regval.name)
            elif regval.is_libc_table_value:
                regval = cast(SSV.SimLibcTableValue, regval)
                return SSV.mk_libc_table_value_deref(regval.name, regval.offset)
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    ("register used in indirect register operand has no base: "
                     + str(regval)
                     + " ("
                     + str(self.imagebase)
                     + ")"))
        else:
            raise SU.CHBSimError(
                self, iaddr, "rhs-op not recognized(C): " + str(op))

    def get_lhs(self, iaddr: str, op: MIPSOperand) -> SimLocation:
        opkind = op.opkind
        if opkind.is_mips_register or opkind.is_mips_special_register:
            return MIPSimRegister(opkind.register)
        elif opkind.is_mips_indirect_register:
            reg = opkind.register
            offset = opkind.offset
            regval = self.get_regval(iaddr, reg)
            if self.instaticlib:
                if regval.is_literal and regval.is_doubleword:
                    regval = cast(SV.SimDoubleWordValue, regval)
                    if regval.value > self.libimagebase.offsetvalue:
                        address: SSV.SimAddress = SSV.SimGlobalAddress(
                            regval).add_offset(offset)
                        return MIPSimMemoryLocation(address)
                    else:
                        raise SU.CHBSimError(
                            self,
                            iaddr,
                            ("Illegal value for location in static lib: "
                             + str(regval)))
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        "Illegal value for location in static lib: " + str(regval))
            elif regval.is_literal:
                regval = cast(SV.SimDoubleWordValue, regval)
                if regval.value > self.imagebase.offsetvalue:
                    address = SSV.SimGlobalAddress(regval).add_offset(offset)
                    return MIPSimMemoryLocation(address)
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        "Register value not recognized: " + str(regval))
            elif regval.is_address:
                regval = cast(SSV.SimAddress, regval)
                address = regval.add_offset(offset)
                return MIPSimMemoryLocation(address)
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    ("get-lhs: operand not recognized: "
                     + str(op)
                     + " (regval: "
                     + str(regval)
                     + ")"))
        else:
            raise SU.CHBSimError(self, iaddr, "get-lhs: " + str(op))

    def get_regval(self, iaddr: str, reg: str, opsize: int = 4) -> SV.SimValue:
        if reg in self.registers:
            if opsize == 4:
                return self.registers[reg]
            elif opsize == 1:
                regval = self.registers[reg]
                if regval.is_literal:
                    regval = cast(SV.SimDoubleWordValue, regval)
                    return regval.simbyte1
                else:
                    return SV.simUndefinedByte
            elif opsize == 2:
                regval = self.registers[reg]
                if regval.is_literal:
                    regval = cast(SV.SimDoubleWordValue, regval)
                    return regval.lowword
                else:
                    return SV.simUndefinedWord
            else:
                raise SU.CHBSimError(self,
                                     iaddr,
                                     "get-regval: opsize: "
                                     + str(opsize)
                                     + " not recognized")
        else:
            self.add_logmsg(iaddr, 'no value for register ' + reg)
            return SV.simUndefinedDW

    def _handle_ctype_toupper(self) -> SSV.SimLibcTableAddress:
        return SSV.mk_libc_table_address('ctype_toupper')

    def _handle_ctype_b(self) -> SSV.SimLibcTableAddress:
        return SSV.mk_libc_table_address('ctype_b')

    def get_memval(
            self,
            iaddr: str,
            address: SSV.SimAddress,
            size: int,
            signextend: bool = False) -> SV.SimValue:
        try:
            if address.is_global_address and self.libapp and self.instaticlib:
                return self.libglobalmem.get(iaddr, address, size)
            if (
                    address.is_global_address
                    and self.is_libc_ctype_toupper(address.offsetvalue)):
                return self._handle_ctype_toupper()
            elif (address.is_global_address
                  and self.is_libc_ctype_b(address.offsetvalue)):
                return self._handle_ctype_b()
            elif address.is_global_address:
                return self.globalmem.get(iaddr, address, size)
            elif address.is_stack_address:
                return self.stackmem.get(iaddr, address, size)
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
                self.add_logmsg(iaddr,
                                'base ' + address.base + ' not yet supported')
                return SV.mk_undefined_simvalue(size)
        except SU.CHBSimError as e:
            self.add_logmsg(
                iaddr,
                ("no value for memory address "
                 + str(address)
                 + ' ('
                 + str(e)
                 + ')'))
            return SV.simUndefinedDW

    def set_lib_memval(
            self,
            iaddr: str,
            address: SSV.SimAddress,
            srcval: SV.SimValue) -> None:
        if address.is_global_address and self.libapp:
            self.libglobalmem.set(iaddr, address, srcval)
            return
        else:
            raise SU.CHBSimError(
                self,
                iaddr,
                "set-lib-memval: " + str(address) + " not supported")

    def set_memval(
            self,
            iaddr: str,
            address: SSV.SimAddress,
            srcval: SV.SimValue) -> None:
        try:
            if address.is_global_address and self.libapp and self.instaticlib:
                self.libglobalmem.set(iaddr, address, srcval)
            if address.is_global_address:
                self.globalmem.set(iaddr, address, srcval)
            elif address.is_stack_address:
                self.stackmem.set(iaddr, address, srcval)
            elif address.is_base_address:
                address = cast(SSV.SimBaseAddress, address)
                base = address.base
                if base not in self.basemem:
                    self.basemem[base] = MIPSimBaseMemory(
                        self, base, buffersize=address.buffersize)
                self.basemem[base].set(iaddr, address, srcval)
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    "set-memval: " + str(address) + " not recognized")
        except SU.CHBSimError as e:
            self.add_logmsg(iaddr, "error in set-memval: " + str(e))
            raise SU.CHBSimError(
                self, iaddr, "set-memval: " + str(address) + ": " + str(e))

    def add_logmsg(self, iaddr: str, msg: str) -> None:
        iaddr = str(iaddr)
        self.fnlog.setdefault(iaddr, [])
        self.fnlog[iaddr].append(msg)

    def get_string_from_memaddr(self, iaddr: str, saddr: SSV.SimAddress) -> str:
        result = ""
        offset = 0
        while True:
            srcaddr = saddr.add_offset(offset)
            srcval = self.get_memval(iaddr, srcaddr, 1)
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

    def get_arg_string(self, iaddr: str, reg: str) -> str:
        saddr = self.registers[reg]
        result = ""
        offset = 0
        if saddr.is_literal:
            saddr = cast(SV.SimLiteralValue, saddr)
            if saddr.is_doubleword:
                saddr = cast(SV.SimDoubleWordValue, saddr)
                if saddr.value > self.imagebase.offsetvalue:
                    saddr = SSV.SimGlobalAddress(saddr)
                    return self.get_string_from_memaddr(iaddr, saddr)
                else:
                    raise SU.CHBSimError(
                        self,
                        iaddr,
                        "String argument is not a valid address: "
                        + str(saddr))
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    "String argument is not a doubleword value: "
                    + str(saddr))
        elif saddr.is_symbolic:
            if saddr.is_string_address:
                saddr = cast(SSV.SimStringAddress, saddr)
                return saddr.stringval
            elif saddr.is_symbol:
                saddr = cast(SSV.SimSymbol, saddr)
                return 'symbol:' + saddr.name
            elif saddr.is_address:
                saddr = cast(SSV.SimAddress, saddr)
                return self.get_string_from_memaddr(iaddr, saddr)
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    "String argument is not recognized: " + str(saddr))
        else:
            raise SU.CHBSimError(
                self,
                iaddr,
                "String argument is not recognized: " + str(saddr))

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append('\nProgram counter: ' + str(self.programcounter))
        lines.append('')
        lines.append('-' * 80)
        lines.append('')
        lines.append('Registers in stack trace format')
        for i in range(0, 8):
            pregs: List[str] = []
            for r in SU.mips_register_order[i * 4: (i + 1) * 4]:
                if r in self.registers:
                    pregs.append(str(self.registers[r]).rjust(16))
                else:
                    pregs.append('?'.rjust(16))
            ppregs = ' '.join(p for p in pregs)
            lines.append('$' + str(i * 4).rjust(2) + '  : ' + ppregs)
        lines.append('=' * 80)
        lines.append('')
        lines.append('-' * 80)
        lines.append('Stack memory:')
        lines.append('-' * 80)
        lines.append(str(self.stackmem))
        lines.append('=' * 80)
        lines.append('')
        lines.append('-' * 80)
        lines.append('Heap memory')
        lines.append('-' * 80)
        for base in self.basemem:
            psize = (
                " (size: "
                + str(self.basemem[base].buffersize)
                + ')'
                if self.basemem[base].has_buffersize()
                else "")
            lines.append('')
            lines.append('Base: ' + base + psize)
            lines.append(str(self.basemem[base]))
        lines.append('=' * 80)
        lines.append('')
        if self.fnlog:
            lines.append('-' * 80)
            lines.append('Log messages:')
            lines.append('-' * 80)
            for a in sorted(self.fnlog):
                lines.append('  ' + str(a) + ' (' + str(len(self.fnlog[a])) + ')')
                for x in self.fnlog[a]:
                    lines.append('    ' + str(x))
            lines.append('=' * 80)
        if self.globalmem.accesses:
            lines.append('')
            lines.append('-' * 80)
            lines.append('Global accesses:')
            lines.append('-' * 80)
            for ma in sorted(self.globalmem.accesses()):
                try:
                    lines.append(
                        "  "
                        + ma
                        + ": "
                        + ",".join(
                            ia for ia in sorted(self.globalmem.accesses()[ma])))
                except Exception:
                    continue
            lines.append('=' * 80)
        # lines.append('\n\nFunction context')
        # lines.append('  ' + str(self.context))
        return '\n'.join(lines)

    def _initialize(self) -> None:
        # obtain dynamically linked library functions
        customstubs = self.simsupport.get_lib_stubs()
        librarystubs = self.app.functionsdata.library_stubs()  # hexaddr -> name
        librarystubs.update(self.simsupport.supplemental_library_stubs())
        for addr in librarystubs:
            name = librarystubs[addr]
            if name in customstubs:
                stub: Optional[MIPSimStub] = customstubs[name](self.app)
            elif name in stubbed_libc_functions:
                stub = stubbed_libc_functions[name](self.app)
            else:
                stub = None
            self.stubs[int(addr, 16)] = (name, stub)

        # set application stubs
        appstubs = self.simsupport.get_app_stubs()
        for addr in appstubs:
            name = (
                self.app.function_name(addr)
                if self.app.has_function_name(addr)
                else addr)
            stub = appstubs[addr](self.app)
            self.appstubs[int(addr, 16)] = (name, stub)

        # set environment variables
        env = self.simsupport.environment_variables
        for key in env:
            self.environment[key] = env[key]

        # obtain dynamically linked library functions for static library
        if self.libapp:
            liblibrarystubs = self.libapp.functionsdata.library_stubs()
            for addr in liblibrarystubs:
                name = liblibrarystubs[addr]
                if name in stubbed_libc_functions:
                    stub = stubbed_libc_functions[name](self.libapp)
                else:
                    stub = None
                self.libstubs[int(addr, 16)] = (name, stub)

        # set functions implemented by libc lookup tables
        ctype_toupper = self.simsupport.get_ctype_toupper()
        ctype_b = self.simsupport.get_ctype_b()
        if ctype_toupper is not None:
            self.ctype_toupper = int(ctype_toupper, 16)
        if ctype_b is not None:
            self.ctype_b = int(ctype_b, 16)
