# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
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

import chb.simulate.SimUtil as SU
import chb.simulate.SimSymbolicValue as SSV
import chb.simulate.SimValue as SV
import chb.util.fileutil as UF


class SimMemory(object):

    def __init__(self,simstate,initialized,name):
        self.simstate = simstate
        self.bigendian = self.simstate.bigendian
        self.mem = {}       # address -> SimByteValue
        self.initialized = initialized
        self.name = name

    def get_size(self): return len(self.mem)

    def get_start_address(self):
        if len(self.mem) > 0:
            return sorted(self.mem.keys())[0]
        raise UF.CHBError(self.name + ' memory is empty')

    def get_extent(self):
        if len(self.mem) > 0:
            lowaddr = sorted(self.mem.keys())[0]
            highaddr = sorted(self.mem.keys())[-1]
            return highaddr - lowaddr

    def set_byte(self,iaddr,address,srcval):
        self.mem[address] = srcval

    def set_symbolic(self,iaddr,address,srcval):
        self.mem[address] = srcval
        if srcval.is_word():
            self.mem[address+1] = srcval
        if srcval.is_doubleword():
            self.mem[address+1] = srcval
            self.mem[address+2] = srcval
            self.mem[address+3] = srcval

    def set(self,iaddr,address,srcval):
        address = address.get_offset_value()
        if srcval.is_symbolic():
            self.mem[address] = srcval
            self.mem[address+1] = srcval
            self.mem[address+2] = srcval
            self.mem[address+3] = srcval
        elif self.bigendian:
            self.set_big_endian(iaddr,address,srcval)
        else:
            self.set_little_endian(iaddr,address,srcval)

    def set_little_endian(self,iaddr,address,srcval):
        if srcval.is_byte():
            self.set_byte(iaddr,address,srcval)
        elif srcval.is_word():
            self.set_byte(iaddr,address,srcval.get_low_byte())
            self.set_byte(iaddr,address+1,srcval.get_high_byte())
        elif srcval.is_doubleword():
            self.set_byte(iaddr,address,srcval.get_byte1())
            self.set_byte(iaddr,address+1,srcval.get_byte2())
            self.set_byte(iaddr,address+2,srcval.get_byte3())
            self.set_byte(iaddr,address+3,srcval.get_byte4())
        else:
            raise SU.CHBSimError(self.simstate,iaddr,
                                    'Type of srcval not recognized: ' + str(srcval))

    def set_big_endian(self,iaddr,address,srcval):
        if srcval.is_byte():
            self.set_byte(iaddr,address,srcval)
        elif srcval.is_word():
            self.set_byte(iaddr,address,srcval.get_high_byte())
            self.set_byte(iaddr,address,srcval.get_low_byte())
        elif srcval.is_doubleword():
            self.set_byte(iaddr,address,srcval.get_byte4())
            self.set_byte(iaddr,address+1,srcval.get_byte3())
            self.set_byte(iaddr,address+2,srcval.get_byte2())
            self.set_byte(iaddr,address+3,srcval.get_byte1())
        else:
            raise SU.CHBSimError(self.simstate,iaddr,
                                 'Type of srcval not recognized: ' + str(srcval))

    def get_byte(self,iaddr,address):
        if address in self.mem:
            return self.mem[address]
        else:
            if self.initialized:
                return SV.simzerobyte
            else:
                raise SU.CHBSimError(self.simstate,iaddr,
                                           self.name + ' memory location at ' + str(hex(address))
                                           + ' not initialized')

    def get(self,iaddr,address,size):
        address = address.get_offset_value()
        if not address in self.mem:
            raise SU.CHBSimError(self.simstate,iaddr,
                                 'Address ' + str(address) + ' not found in memory')
        if self.mem[address].is_symbolic():
            return self.mem[address]
        if size == 1:
            return self.get_byte(iaddr,address)
        if self.bigendian:
            return self.get_big_endian(iaddr,address,size)
        else:
            return self.get_little_endian(iaddr,address,size)

    def get_char_string(self,iaddr,address,size):
        address = address.get_offset_value()
        if not address in self.mem:
            raise SU.CHBSimError(self.simstate,iaddr,
                                'Address ' + str(address) + ' not found in memory')
        if self.mem[address].is_symbolic():
            return '----'
        if size == 4:
            b1 = self.get_byte(iaddr,address+3)
            b2 = self.get_byte(iaddr,address+2)
            b3 = self.get_byte(iaddr,address+1)
            b4 = self.get_byte(iaddr,address)
            result = ''
            if b1.value == 0 and b2.value == 0 and b3.value == 0 and b4.value == 0:
                return ''
            if self.bigendian:
                seq = [ b4, b3, b2, b1 ]
            else:
                seq = [ b1, b2, b3, b4 ]
            for b in seq:
                if b.value > 10 and b.value < 127:
                    result += chr(b.value)
                else:
                    result += '?'
            return result
        return '?'

    def get_little_endian(self,iaddr,address,size):
        if size == 2:
            b1 = self.get_byte(iaddr,address)
            b2 = self.get_byte(iaddr,address+1)
            return SV.compose_simvalue([b1, b2])
        elif size == 4:
            b1 = self.get_byte(iaddr,address)
            b2 = self.get_byte(iaddr,address+1)
            b3 = self.get_byte(iaddr,address+2)
            b4 = self.get_byte(iaddr,address+3)
            try:
                return SV.compose_simvalue([b1, b2, b3, b4 ])
            except UF.CHBError as e:
                raise SU.CHBSimError(self.simstate,iaddr,
                                     'Error at value at address: ' + str(address)
                                     + ': ' + str(e))
        else:
            raise SU.CHBSimError(self.simstate,iaddr,
                                       'Size of memory value request not supported: '
                                       + str(size))

    def get_big_endian(self,iaddr,address,size):
        if size == 2:
            b1 = self.get_byte(iaddr,address+1)
            b2 = self.get_byte(iaddr,address)
            return SV.compose_simvalue([b1,b2])
        elif size == 4:
            b1 = self.get_byte(iaddr,address+3)
            b2 = self.get_byte(iaddr,address+2)
            b3 = self.get_byte(iaddr,address+1)
            b4 = self.get_byte(iaddr,address)
            return SV.compose_simvalue([b1, b2, b3, b4 ])
        else:
            raise SU.CHBSimError(self.simstate,iaddr,
                                 'Size of memory value request not supported: '
                                 + str(size))

    def to_byte_string(self):
        if len(self.mem) > 0:
            s = ''
            lowaddr = sorted(self.mem.keys())[0]
            highaddr = sorted(self.mem.keys())[-1]
            for a in range(lowaddr,highaddr+1):
                if a in self.mem:
                    byte = self.mem[a].value
                else:
                    byte = 0
                b = '{0:#0{1}x}'.format(byte,4)[2:]
                s += b
            n = 80
            stringlist = [ s[i:i+n] for i in range(0,len(s),n) ]
            return '\n'.join(stringlist)
        return ''

    def mk_address(self,offset):
        if self.name == 'global':
            return SSV.SimGlobalAddress(SV.mk_simvalue(offset))
        elif self.name == 'stack':
            return SSV.SimStackAddress(SV.mk_simvalue(offset))
        else:
            return SSV.SimBaseAddress(self.name,SV.mk_simvalue(offset))

    def __str__(self):
        lines = []
        if len(self.mem) > 0:
            lowaddr = sorted(self.mem.keys())[0]
            highaddr = sorted(self.mem.keys())[-1]
            if lowaddr < 0:
                lowaddr = ((lowaddr // 4) - 1) * 4
            else:
                lowaddr = (lowaddr // 4) * 4
            for a in range(lowaddr,highaddr,4):
                try:
                    if a in self.mem:
                        address = self.mk_address(a)
                        try:
                            charstring = self.get_char_string(0,address,4)
                        except:
                            charstring = '?'
                        lines.append(str(hex(a)).rjust(12)
                                     + '  ' + str(a).rjust(12)
                                     + '  ' + str(self.get(0,address,4))
                                     + '  ' + str(charstring))
                except SU.CHBSimValueUndefinedError:
                    lines.append(str(hex(a)).rjust(12) + '  ?')
                except SU.CHBSimError:
                    lines.append(str(hex(a)).rjust(12) + '  ?')

        return '\n'.join(lines)


class SimGlobalMemory(SimMemory):

    def __init__(self,simstate):
        SimMemory.__init__(self,simstate,True,'global')



class SimStackMemory(SimMemory):
    
    def __init__(self,simstate):
        SimMemory.__init__(self,simstate,False,'stack')
        

