# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2020 Henny Sipma
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

import chb.util.fileutil as UF

import chb.mipsimulate.MIPSimLocation as MSL
import chb.mipsimulate.MIPSimMemory as MM
import chb.mipsimulate.MIPSimStubs as Stubs

import chb.simulate.SimMemory as M
import chb.simulate.SimSymbolicValue as SSV
import chb.simulate.SimValue as SV

import chb.simulate.SimUtil as SU

class FunctionContext(object):

    def __init__(self):
        self.functions = []

    def is_empty(self): return self.functions == []

    def push(self,fn): self.functions.append(fn)

    def pop(self):
        if self.is_empty():
            return 'nothing to pop'
        else:
            return self.functions.pop()

    def peek(self): return self.functions[len(self.functions)-1]

    def restore(self,faddr):
        while self.peek() != faddr:
            self.pop()

    def __str__(self):
        return ', '.join(self.functions)


class MIPSimulationState(object):

    def __init__(self,app,basename,
                 bigendian=False,
                 simsupport=None,   # support class with custom initialization and stubs
                 baseaddress=0,     # load address, to be added to imagebase
                 libapp=None,   # library to statically include functions from
                 xapp=None):    # target executable for dynamic loading
        self.app = app
        self.basename = basename
        self.baseaddress = baseaddress
        self.bigendian = bigendian
        self.simsupport = simsupport

        self.imagebase = None
        self.context = FunctionContext()

        # registers and memory
        self.registers = {}      # register name -> SimValue
        self.registers['zero'] = SV.SimDoubleWordValue(0)        
        self.stackmem = MM.MIPSimStackMemory(self)
        self.globalmem = MM.MIPSimGlobalMemory(self,self.app)
        self.basemem = {} # base -> MM.MIPSimBaseMemory

        # static library (optional)
        self.libapp = libapp
        if self.libapp:
            self.libstubs = {}   # int (int-address) -> (name,stub)
            self.libglobalmem = MM.MIPSimGlobalMemory(self,libapp)
            self.static_lib = {}  # function-name -> function address in static lib
            libimgbase = self.libapp.get_elf_header().get_image_base()
            self.libimagebase = SSV.SimGlobalAddress(SV.SimDoubleWordValue(int(libimgbase,16)))

        self.instaticlib = False

        # target executable for dynamic loading (optional)
        self.xapp = xapp
        if self.xapp:
            self.xglobalmem = MM.MIPSimGlobalMemory(self,xapp)
            
        # log
        self.fnlog = {}          # iaddr -> msg list2
        
        # program counter
        self.programcounter = None                 # SimAddress
        self.delayed_programcounter = None         # SimAddress

        # environment
        self.environment = {}   # string -> string
        self.nvram = {}   # string -> string ; non-volatile ram default values
        self.network_input = {}    # string -> f() -> string
        
        self.stubs = {}   # int (int-address) -> (name,stub)
        self._initialize()

    def function_start_initialization(self):
        self.registers['sp'] = SSV.SimStackAddress(SV.simZero)   # stackpointer
        for reg in [ 'ra','gp','fp','s0','s1','s2','s3','s4','s5','s6','s7' ]:
            self.registers[reg] = SSV.SimSymbol(reg + '_in')
        self.simsupport.do_initialization(self)

    def set_base_address(self,base): self.baseaddress = base

    def set_image_base(self,value):
        self.imagebase = SSV.SimGlobalAddress(SV.SimDoubleWordValue(int(value,16)))    
    

    # --- context ---

    def push_context(self,faddr): self.context.push(faddr)

    def pop_context(self): return self.context.pop()

    def restore_context(self,faddr): self.context.restore(faddr)

    # --- stubs ---

    def get_function_stub(self,addrvalue): return self.stubs[addrvalue][1]    

    # --- statically included library ---

    def set_in_static_lib(self,v): self.instaticlib = v

    def set_static_lib(self,libfns):
        for name in libfns:
            self.static_lib[name] = libfns[name]

    def get_lib_function_stub(self,addrvalue):
        return self.libstubs[addrvalue][1]

    # --- environment / nvram ---

    def has_environment_variable(self,name): return name in self.environment

    def get_environment_variable_value(self,name):
        if self.has_environment_variable(name):
            return self.environment[name]
        else:
            raise UF.CHBError('Value for environment variable ' + name + ' not found')

    def set_environment_variable(self,name,value):
        self.environment[name] = value

    def set_environment(self,d):
        for key in d:
            self.environment[key] = d[key]

    def set_nvram(self,d):
        for key in d:
            self.nvram[key] = d[key]

    # --- network input ---

    def set_network_input(self,iaddr,f):
        self.network_input[iaddr] = f

    def get_network_input(self,iaddr):
        if self.has_network_input(iaddr):
            return self.network_input[iaddr]
        else:
            raise CHBError('No network input found for address ' + iaddr)

    def has_network_input(self,iaddr):
        return iaddr in self.network_input

    # --- program counter ---
        
    def set_program_counter(self,address):   # SimAddress
        self.programcounter = address

    def set_delayed_program_counter(self,address):   # SimAddress
        self.delayed_programcounter = address

    def get_program_counter(self): return self.programcounter

    def increment_program_counter(self):
        if self.delayed_programcounter:
            if self.delayed_programcounter.is_symbol():
                self.programcounter = self.delayed_programcounter
                self.delayed_programcounter = None
            elif self.delayed_programcounter.is_global_address():
                iaddr = hex(self.programcounter.get_offset_value()-4)
                addrvalue = self.delayed_programcounter.get_offset().value
                if self.libapp and addrvalue in self.static_lib:
                    raise SU.CHBSimStaticLibFunction(iaddr,self.static_lib[addrvalue],self.registers)
                if addrvalue in self.stubs:
                    if self.stubs[addrvalue][1]:
                        msg = self.get_function_stub(addrvalue).simulate(iaddr,self)
                        print('     ' + hex(addrvalue) + ': ' + msg)
                        self.programcounter = self.get_regval(addrvalue,'ra')
                        self.delayed_programcounter = None
                    else:
                        print('Missing stub: ' + self.stubs[addrvalue][0])
                        exit(1)
                elif self.libapp and self.instaticlib and addrvalue in self.libstubs:
                    if self.libstubs[addrvalue][1]:
                        msg = self.get_lib_function_stub(addrvalue).simulate(iaddr,self)
                        print('    ' + hex(addrvalue) + ': ' + msg)
                        if not 'longjmp' in msg:
                            self.programcounter = self.get_regval(addrvalue,'ra')
                        self.delayed_programcounter = None
                    else:
                        print('Missing stub: ' + self.libstubs[addrvalue][0])
                        exit(1)
                else:
                    self.programcounter = self.delayed_programcounter
                    self.delayed_programcounter = None
            else:
                self.programcounter = self.delayed_programcounter
                self.add_logmsg(str(self.delayed_programcounter),
                                'instruction pointer is not a global memory address')
        else:
            self.programcounter = self.programcounter.add_offset(4)

    # --- registers and memory ---

    def set_register(self,iaddr,reg,srcval): self.registers[reg] = srcval

    def set(self,iaddr,dstop,srcval):
        size = dstop.get_size()
        if srcval.is_literal() and (not srcval.is_defined()):
            self.add_logmsg(iaddr,'Source value is undefined: ' + str(dstop))
        lhs = self.get_lhs(iaddr,dstop)
        if lhs.is_register():
            self.set_register(iaddr,lhs.reg,srcval)
        elif lhs.is_memory_location():
            self.set_memval(iaddr,lhs.get_address(),srcval)
        else:
            raise SU.CHBSimError(self,iaddr,'lhs not recognized: ' + str(lhs))
        return lhs

    def get_rhs(self,iaddr,op,opsize=4):
        opkind = op.get_mips_opkind()
        if opkind.is_mips_register() or opkind.is_mips_special_register():
            reg = opkind.get_mips_register()
            return self.get_regval(iaddr,reg,opsize)
        elif opkind.is_mips_immediate():
            return SV.mk_simvalue(opsize,opkind.get_value())
        elif opkind.is_mips_indirect_register():
            reg = opkind.get_mips_register()
            offset = opkind.get_offset()
            regval = self.get_regval(iaddr,reg)
            if not regval.is_defined():
                return SV.mk_undefined_simvalue(opsize)
            if regval.is_string_address() and opsize==1:
                regstring = regval.get_string()
                if offset == len(regstring):
                    return SV.SimByteValue(0)
                elif offset > len(regstring):
                    print('Accessing string value out of bounds')
                    exit(1)
                else:
                    return SV.mk_simvalue(ord(regval.get_string()[offset]),size=1)
            if regval.is_symbol():
                base = regval.get_name()
                if not base in self.basemem:
                    self.basemem[base] = MM.MIPSimBaseMemory(self,base)
                address = SSV.mk_base_address(base,offset=offset)
                return self.get_memval(iaddr,address,opsize)
            elif regval.is_address():
                address = regval.add_offset(offset)
                return self.get_memval(iaddr,address,opsize)
            elif (regval.is_literal() and self.instaticlib
                  and regval.value > self.libimagebase.get_offset_value()):
                address = SSV.mk_global_address(regval.value + offset)
                return self.get_memval(iaddr,address,opsize)
            elif (regval.is_literal() and regval.value > self.imagebase.get_offset_value()):
                address = SSV.mk_global_address(regval.value + offset)
                return self.get_memval(iaddr,address,opsize)
            elif regval.is_literal() and regval.value <= self.imagebase.get_offset_value():
                print('Invalid address: ' + str(regval))
                return SV.mk_undefined_simvalue(opsize)
            elif regval.is_string_address():
                s = regval.get_string()
                if offset < len(s):
                    return SV.mk_simvalue(ord(s[0]),size=opsize)
                elif offset == len(s):
                    return SV.mk_simvalue(0,size=opsize)   # null terminator
                else:
                    raise SU.CHBSimError(self,iaddr,
                                         'string address: ' + s.get_string()
                                         + ' with offset: ' + str(offset))
            else:
                raise SU.CHBSimError(self,iaddr,
                                     'register used in indirect register operand has no base: '
                                     + str(regval) + ' (' + str(self.imagebase) + ')')
        else:
            raise SU.CHBSimError(self,iaddr,'rhs-op not recognized(C): ' + str(op))

    def get_lhs(self,iaddr,op):
        opkind = op.get_mips_opkind()
        if opkind.is_mips_register() or opkind.is_mips_special_register():
            return MSL.MIPSimRegister(opkind.get_mips_register())
        elif opkind.is_mips_indirect_register():
            reg = opkind.get_mips_register()
            offset = opkind.get_offset()
            regval = self.get_regval(iaddr,reg)
            if self.instaticlib:
                if regval.is_literal() and regval.value > self.libimagebase.get_offset_value():
                    address = SSV.SimGlobalAddress(regval).add_offset(offset)
                    return MSL.MIPSimMemoryLocation(address)
            if regval.is_literal() and regval.value > self.imagebase.get_offset_value():
                address = SSV.SimGlobalAddress(regval).add_offset(offset)
                return MSL.MIPSimMemoryLocation(address)
            elif regval.is_address():
                address = regval.add_offset(offset)
                return MSL.MIPSimMemoryLocation(address)
            else:
                raise SU.CHBSimError(self,iaddr,
                                     'get-lhs: operand not recognized: ' + str(op)
                                     + ' (regval: ' + str(regval) + ')')
        else:
            raise SU.CHBSimError(self,iaddr,'get-lhs: ' + str(op))

    def get_regval(self,iaddr,reg,opsize=4):
        if reg in self.registers:
            if opsize == 4:
                return self.registers[reg]
            elif opsize == 1:
                return self.registers[reg].get_byte1()
            elif opsize == 2:
                return self.registers[reg].get_low_word()
            else:
                raise SU.CHBSimError(self.iaddr,
                                     'get-regval: opsize: ' + str(opsize)
                                     + ' not recognized')
        else:
            self.add_logmsg(iaddr,'no value for register ' + reg)
            return SV.simUndefinedDW

    def get_memval(self,iaddr,address,size,signextend=False):
        try:
            if address.is_address():
                if address.is_global_address() and self.libapp and self.instaticlib:
                    return self.libglobalmem.get(iaddr,address,size)
                elif address.is_global_address():
                    return self.globalmem.get(iaddr,address,size)
                elif address.is_stack_address():
                    return self.stackmem.get(iaddr,address,size)
                elif address.is_base_address() and address.get_base() in self.basemem:
                    return self.basemem[address.get_base()].get(iaddr,address,size)
                else:
                    self.add_logmsg(iaddr,'base ' + address.base
                                    + ' not yet supported')
                    return SV.mk_undefined_simvalue(size)
            else:
                self.add_logmsg(iaddr,'attempt to address memory with absolute value: '
                                + str(address))
                return SV.simUndefinedDW
        except SU.CHBSimError as e:
            self.add_logmsg(iaddr,'no value for memory address ' + str(address)
                            + ' (' + str(e) + ')')
            return SV.simUndefinedDW

    def set_memval(self,iaddr,address,srcval):
        try:
            if address.is_address():
                if address.is_global_address() and self.libapp and self.instaticlib:
                    return self.libglobalmem.set(iaddr,address,srcval)
                if address.is_global_address():
                    self.globalmem.set(iaddr,address,srcval)
                elif address.is_stack_address():
                    self.stackmem.set(iaddr,address,srcval)
                elif address.is_base_address():
                    base = address.get_base()
                    if not base in self.basemem:
                        self.basemem[base] = MM.MIPSimBaseMemory(self,base,
                                                                 buffersize=address.get_buffer_size())
                    self.basemem[base].set(iaddr,address,srcval)
                else:
                    raise SU.CHBSimError(self,iaddr,'set-memval: ' + str(address) + ' not recognized')
            else:
                self.add_logmsg(iaddr,'attempt to address memory with absolute value: '
                                + str(address))
        except SU.CHBSimError as e:
            self.add_logmsg(iaddr,'error in set-memval: ' + str(e))
            raise SU.CHBSimError(self,iaddr,'set-memval: ' + str(address) + ': ' + str(e))

    def add_logmsg(self,iaddr,msg):
        iaddr = str(iaddr)
        self.fnlog.setdefault(iaddr,[])
        self.fnlog[iaddr].append(msg)

    def get_arg_string(self,iaddr,reg):
        saddr = self.registers[reg]
        result = ''
        offset = 0
        if saddr.is_literal():
            if saddr.value > self.imagebase.get_offset_value():
                saddr = SSV.SimGlobalAddress(saddr)
            else:
                raise SU.CHBSimError(self,iaddr,
                                     'String argument is not a valid address: ' + str(saddr))
        elif saddr.is_string_address():
            return saddr.get_string()
        elif saddr.is_symbol():
            return 'symbol:' + saddr.get_name()
        while True:
            srcaddr = saddr.add_offset(offset)
            srcval = self.get_memval(iaddr,srcaddr,1)
            if srcval.is_defined():
                if srcval.value == 0:
                    break
                else:
                    result += chr(srcval.value)
                    offset += 1
            else:
                break
        return result


    def __str__(self):
        lines = []
        lines.append('\nProgram counter: ' + str(self.programcounter))
        lines.append('')
        lines.append('-' * 80)
        # lines.append('Registers:')
        # lines.append('-' * 80)
        # for r in sorted(self.registers):
        #    lines.append(r.ljust(10) + str(self.registers[r]))
        # lines.append('=' * 80)
        lines.append('')
        lines.append('Registers in stack trace format')
        for i in range(0,8):
            pregs = []
            for r in SU.mips_register_order[i*4:(i+1)*4]:
                if r in self.registers:
                    pregs.append(str(self.registers[r]).rjust(16))
                else:
                    pregs.append('?'.rjust(16))
            pregs = ' '.join(p for p in pregs)                     
            lines.append('$' + str(i*4).rjust(2) + '  : ' + pregs)
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
            psize = (' (size: ' + str(self.basemem[base].get_buffersize()) + ')'
                     if self.basemem[base].has_buffersize() else '')
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
                lines.append('  ' + str(a))
                for x in self.fnlog[a]:
                    lines.append('    ' + str(x))
            lines.append('=' * 80)
        if self.globalmem.accesses:
            lines.append('')
            lines.append('-' * 80)
            lines.append('Global accesses:')
            lines.append('-' * 80)
            for ma in sorted(self.globalmem.accesses):
                lines.append('  ' + ma + ': '
                             + ','.join(ia for ia in sorted(self.globalmem.accesses[ma])))
            lines.append('=' * 80)
        lines.append('\n\nFunction context')
        lines.append('  ' + str(self.context))
        return '\n'.join(lines)

    def _initialize(self):
        # obtain dynamically linked library functions
        customstubs = self.simsupport.get_lib_stubs()
        librarystubs = self.app.functionsdata.get_library_stubs()  # hexaddr -> name
        librarystubs.update(self.simsupport.get_supplemental_library_stubs())
        for addr in librarystubs:
            name = librarystubs[addr]
            if name in customstubs:
                stub = customstubs[name](self.app)
            elif name in Stubs.stubbed_libc_functions:
                stub = Stubs.stubbed_libc_functions[name](self.app)
            else:
                stub = None
            self.stubs[int(addr,16)] = (name,stub)

        # set environment variables
        env = self.simsupport.get_environment()
        for key in env:
            self.environment[key] = env[key]

        # obtain dynamically linked library functions for static library
        if self.libapp:
            liblibrarystubs = self.libapp.functionsdata.get_library_stubs()
            for addr in liblibrarystubs:
                name = liblibrarystubs[addr]
                if name in Stubs.stubbed_libc_functions:
                    stub = Stubs.stubbed_libc_functions[name](self.libapp)
                else:
                    stub = None
                self.libstubs[int(addr,16)] = (name,stub)
        
