# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
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

import chb.simulate.SimAddress as SA
import chb.simulate.SimMemory as M
import chb.simulate.SimUtil as SU
import chb.simulate.SimValue as SV
import chb.simulate.SimLocation as SL


class SimulationState(object):

    def __init__(self,asmfn):
        self.asmfn = asmfn          # AsmFunction
        self.imagebase = None
        self.uninitializedregion = None
        self.flags = {}             # flagname -> SimBoolValue
        self.registers = {}         # register name -> SimDoubleWordValue
        self.globalmem = M.SimGlobalMemory(self)        
        self.stackmem = M.SimStackMemory(self)
        self.fnlog = {}             # iaddr -> msg list
        self.registers['esp'] = SA.SimStackAddress(0)
        self.registers['ebp'] = SV.mk_symbolic_simvalue('ebp-in')
        self.registers['eax'] = SV.mk_symbolic_simvalue('eax-in')
        self.registers['ecx'] = SV.mk_symbolic_simvalue('ecx-in')
        self.stackmem.set(0,0,SA.SimReturnAddress())
        self.flags['DF'] = SV.simflagclr         # direction forward
        self.flags['CF'] = SV.simflagclr         # no carry
        self.flags['PF'] = SV.simflagclr         # even parity
        self.flags['ZF'] = SV.simflagclr         # no zero result
        self.flags['SF'] = SV.simflagclr         # unsigned result
        self.flags['OF'] = SV.simflagclr         # no overflow occurred

    def set_image_base(self,value): 
        self.imagebase = SA.SimGlobalAddress(int(value,16))

    def set_initial_register(self,reg,regval):
        if SU.is_full_reg(reg):
            self.registers[reg] = regval
        else:
            raise UF.CHBError('Register ' + reg + ' cannot be initialized')

    def set_uninitialized_region(self,low,high):
        self.uninitializedregion = (SV.mk_global_hex_address(low),
                                        SV.mk_global_hex_address(high))

    def is_uninitialized_global_mem(self,address):
        if not self.uninitializedregion is None:
            (low,high) = self.uninitializedregion
            return low <= address and address < high
        return False

    def set_register(self,iaddr,reg,srcval):
        if SU.is_full_reg(reg):
            if srcval.is_doubleword():
                self.registers[reg] = srcval
            else:
                raise SU.CHBSimError(
                    self,
                    iaddr,
                    'Cannot assign byte/word value to full register: ' + str(srcval)
                    + ' (width: ' + str(srcval.get_width()) + ')')
        elif SU.is_half_reg(reg):
            fullreg = SU.fullregmap[reg]
            fullregval = self.get_regval(iaddr,fullreg)
            newval = fullregval.set_word(srcval)
            self.set_register(iaddr,fullreg,newval)
        elif SU.is_qlow_reg(reg):
            fullreg = SU.fullregmap[reg]
            fullregval = self.get_regval(iaddr,fullreg)
            newval = fullregval.set_low_byte(srcval)
            self.set_register(iaddr,fullreg,newval)
        elif is_qhigh_reg(reg):
            fullreg = fullregmap(reg)
            fullregval = self.get_regval(iaddr,fullreg)
            newval = fullregval.set_snd_byte(srcval)
            self.set_register(iaddr,fullreg,newval)
        else:
            self.registers[reg] = srcval

    def set(self,iaddr,dstop,srcval):
        if srcval.undefined:
            self.add_logmsg(iaddr,'Source value is undefined: ' + str(dstop))
        lhs = self.get_lhs(iaddr,dstop)
        if lhs.is_register():
            self.set_register(iaddr,lhs.reg,srcval)

        elif lhs.is_double_register():
            self.set_register(iaddr,lhs.reglow,srcval.get_low_half())
            self.set_register(iaddr,lhs.reghigh,srcval.get_high_half())

        elif lhs.is_memory_location():
            if lhs.is_global():
                self.globalmem.set(iaddr,lhs.get_address(),srcval)
                self.add_logmsg(iaddr,str(lhs) + ' := '  + str(srcval))
            elif lhs.is_stack():
                self.stackmem.set(iaddr,lhs.get_offset(),srcval)
            else:
                self.add_logmsg(iaddr,'Destination location not found: ' + str(dstop))
        else:
            self.add_logmsg(iaddr,'Destination location not found: ' + str(dstop))

    def push_value(self,iaddr,simval):
        stackoffset = self.get_regval(iaddr,'esp').get_offset()
        newoffset = stackoffset - 4
        self.registers['esp'] = SA.SimStackAddress(newoffset)
        self.stackmem.set(iaddr,newoffset,simval)

    def pop_value(self,iaddr):
        stackoffset = self.get_regval(iaddr,'esp').get_offset()
        newoffset = stackoffset + 4
        self.registers['esp'] = SA.SimStackAddress(newoffset)
        return self.stackmem.get(iaddr,stackoffset,4)

    def set_flag(self,flag):
        if flag in self.flags:
            self.flags[flag] = SV.simflagset
        else:
            raise SU.CHBSimError(self,iaddr,
                                       'flag not recognized: ' + flag)

    def clear_flag(self,flag):
        if flag in self.flags:
            self.flags[flag] = SV.simflagclr
        else:
            raise SU.CHBSimError(self,iaddr,
                                       'flag not recognized: ' + flag)

    def undefine_flag(self,flag):
        if flag in self.flags:
            self.flags[flag] = SV.simflagundef
        else:
            raise SU.CHBSimError(self,iaddr,
                                       'flag not recognized: ' + flag)

    def update_flag(self,flag,v):
        if v is None:
            self.undefine_flag(flag)
        elif v:
            self.set_flag(flag)
        else:
            self.clear_flag(flag)

    def get_flag_value(self,flag):
        if flag in self.flags:
            if self.flags[flag].undefined:
                return None
            else:
                return self.flags[flag].value
        else:
            raise SU.CHBSimError(self,iaddr,
                                       'flag not recognized: ' + flag)

    def get_rhs(self,iaddr,op):
        opsize = op.get_size()
        opkind = op.get_opkind()
        if opkind.is_flag():
            flag = opkind.get_flag()
            if flag in self.flags:
                return self.flags[flag]
            else:
                raise SU.CHBSimError(self,iaddr,
                                           'flag value ' + flag + ' not found')

        elif opkind.is_register():
            reg = opkind.get_register()
            return self.get_regval(iaddr,reg)

        elif opkind.is_double_register():
            lowreg = opkind.get_reg_low()
            highreg = opkind.get_reg_high()
            lowval = self.get_regval(iaddr,lowreg)
            highval = self.get_regval(iaddr,highreg)
            return lowval.to_double_size(highval)

        elif opkind.is_immediate():
            return SV.mk_simvalue(op.get_size(),opkind.get_value())

        elif opkind.is_indirect_register():
            reg = opkind.get_register()
            offset = opkind.get_offset()
            regval = self.get_regval(iaddr,reg)
            if regval.is_address():
                address = regval.add_offset(offset)
                return self.get_memval(iaddr,address,op.get_size())
            elif regval.value > self.imagebase.value:
                address = SA.SimGlobalAddress(regval.value)
                address = address.add_offset(offset)
                return  self.get_memval(iaddr,address,op.get_size())
            else:
                raise SU.CHBSimError(self,iaddr,
                                        'register used in indirect register operand has no base: '
                                        + str(regval) + ' (' + str(self.imagebase) + ')')

        elif opkind.is_scaled_indirect_register():
            basereg = opkind.get_base_register()
            indexreg = opkind.get_ind_register()
            offset = opkind.get_offset()
            scale = opkind.get_scale()
            if (not basereg is None) and indexreg is None and scale == 1:
                regval = self.get_regval(iaddr,basereg)
                if regval.is_address():
                    address = regval.add_offset(offset)
                    return self.get_memval(iaddr,address,op.get_size())
            elif (not basereg is None) and (not indexreg is None) and scale == 1:
                baseval = self.get_regval(iaddr,basereg)
                indexval = self.get_regval(iaddr,indexreg)
                if indexval.is_address():
                    address = indexval.add_offset(offset)
                    address = address.add_offset(scale * baseval.to_signed_int())
                    return self.get_memval(iaddr,address,op.get_size())
                else:
                    raise SU.CHBSimError(self,iaddr,'rhs-op not recognized(A): ' + str(op))
            else:
                raise SU.CHBSimError(self,iaddr,'rhs-op not recognized(B): ' + str(op))
        else:
            raise SU.CHBSimError(self,iaddr,'rhs-op not recognized(C): ' + str(op))

    def get_lhs(self,iaddr,op):
        opkind = op.get_opkind()
        if opkind.is_register():
            return SL.SimRegister(opkind.get_register())

        elif opkind.is_double_register():
            return SL.SimDoubleRegister(opkind.get_reg_low(), opkind.get_reg_high())
        
        elif opkind.is_indirect_register():
            reg = opkind.get_register()
            offset = opkind.get_offset()
            regval = self.get_regval(iaddr,reg)
            if regval.is_address():
                return SL.SimMemoryLocation(regval.add_offset(offset))
            elif regval.value > self.imagebase.value:
                address = SA.SimGlobalAddress(regval.value + offset)
                return SL.SimMemoryLocation(address)
            else:
                raise SU.CHBSimError(self,iaddr,
                                        'get-lhs: operand not recognized: ' + str(op)
                                        + ' (regval: ' + str(regval) + ')')
            
        elif opkind.is_scaled_indirect_register():
            basereg = opkind.get_base_register()
            indexreg = opkind.get_ind_register()
            offset = opkind.get_offset()
            scale = opkind.get_scale()
            if (not basereg is None) and indexreg is None and scale == 1:
                regval = self.get_regval(iaddr,basereg)
                if regval.is_address():
                    return SL.SimMemoryLocation(regval.add_offset(offset))
                else:
                    raise SU.CHBSimError(self,iaddr,
                                            'get-lhs: operand not recognized: ' + str(op)
                                            + ' produces: ' + str(regval))
            elif (not basereg is None) and (not indexreg is None) and scale == 1:
                baseregval = self.get_regval(iaddr,basereg)
                indexval = self.get_regval(iaddr,indexreg)
                if indexval.is_address():
                    memaddress = indexval.add_offset(baseregval.to_signed_int())
                    memaddress = memaddress.add_offset(offset)
                    return SL.SimMemoryLocation(memaddress)
                else:
                    raise SU.CHBSimError(self,iaddr,'get-lhs: operand not recognized(A): ' + str(op))
            else:
                raise SU.CHBSimError(self,iaddr,'get-lhs: operand not recognized(B): ' + str(op)
                                        + ' (scaled indirect)')
        else:
            raise SU.CHBSimError(self,iaddr,'get-lhs: operand not recognized(C): ' + str(op))

    def get_address_val(self,iaddr,op):
        opkind = op.get_opkind()
        if opkind.is_indirect_register():
            reg = opkind.get_register()
            offset = opkind.get_offset()
            regval = self.get_regval(iaddr,reg)
            if regval.undefined:
                return SV.simundefined
            elif regval.is_address():
                return regval.add_offset(offset)
            elif regval > self.imagebase.value:
                return SA.SimGlobalAddress(regval.value + offset)
            else:
                raise SU.CHBSimError(self,iaddr,
                                        'get-address-val: indirect register: ' + str(op))
        elif opkind.is_scaled_indirect_register():
            basereg = opkind.get_base_register()
            indexreg = opkind.get_ind_register()
            scale = opkind.get_scale()
            if indexreg is None and scale == 1:
                offset = opkind.get_offset()
                regval = self.get_regval(iaddr,basereg)
                print('Regval for ' + basereg + ': ' + str(regval))
                print('Esp: ' + str(self.registers['esp']))
                if regval.is_address():
                    return regval.add_offset(offset)
                elif regval > self.imagebase.value:
                    return SA.SimGlobalAddress(regval.value + offset)
                else:
                    raise SU.CHBSimError(self,iaddr,
                                               'get-address-val: indirect-scaled-register: '
                                               + str(basereg))
            else:
                raise SU.CHBSimError(self,iaddr,
                                           'get-address-val: indirect-scaled-register: '
                                           + str(basereg) + ', ' + str(indexreg))
        else:
            raise SU.CHBSimError(self,iaddr,'get-address-val: ' + str(op))
                

    def get_regval(self,iaddr,reg):
        if SU.is_half_reg(reg):
            fullreg = SU.get_full_reg(reg)
            if fullreg in self.registers:
                return self.registers[fullreg].get_low_word()
            raise SU.CHBSimError(self,iaddr,
                                       'get_regval: no value found  for '
                                       + reg + ' (' + fullreg + ')')
        elif SU.is_qlow_reg(reg):
            fullreg = SU.get_full_reg(reg)
            if fullreg in self.registers:
                return self.registers[fullreg].get_low_byte()
            raise SU.CHBSimError(self,iaddr,
                                        'get_regval: no value found for '
                                        + reg + ' (' + fullreg + ')')
        elif SU.is_qhigh_reg(reg):
            fullreg = SU.get_full_reg(reg)
            if fullreg in self.registers:
                return self.registers[fullreg].get_snd_byte()
            raise SU.CHBSimError(self,iaddr,
                                       'get_regval: no value found for '
                                       + reg + ' (' + fullreg + ')')
        elif reg in self.registers:
            return self.registers[reg]
        else:
            self.add_logmsg(iaddr,'no value for register ' + reg)
            return SV.simundefined

    def get_memval(self,iaddr,address,size,signextend=False):
        if address.is_address():
            if address.is_global_address():
                return self.globalmem.get(iaddr,address.value,size)
            elif address.is_stack_address():
                return self.stackmem.get(iaddr,address.get_offset(),size)
            else:
                self.add_logmsg(iaddr,'base ' + address.base
                                    + ' not yet supported')
                return SV.simzero

        else:
            self.add_logmsg(iaddr,'attempt to address memory with absolute value: '
                                + str(address))

    def add_logmsg(self,iaddr,msg):
        if not iaddr in self.fnlog: self.fnlog[iaddr] =  []
        self.fnlog[iaddr].append(msg)

    def __str__(self):
        lines = []
        lines.append('\nFlags:')
        for f in sorted(self.flags):
            lines.append(f.ljust(10) + str(self.flags[f]))
        lines.append('\nRegisters:')
        for r in sorted(self.registers):
            lines.append(r.ljust(10) + str(self.registers[r]))
        lines.append('\nGlobal memory: (size: '
                         + str(self.globalmem.get_size()) + ', extent: '
                         + str(self.globalmem.get_extent()) + ')' )
        lines.append(str(self.globalmem))
        lines.append(self.globalmem.to_byte_string())
        lines.append('\nStack memory:')
        lines.append(str(self.stackmem))
        if len(self.fnlog) > 0:
            lines.append('\nLog messages:')
            for a in sorted(self.fnlog):
                lines.append(str(a).ljust(14) + '; '.join([ str(x) for x in self.fnlog[a]]))
        return '\n'.join(lines)
        
            
            
