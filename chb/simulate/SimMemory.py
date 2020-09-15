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

import chb.simulate.SimValue as SV

class SimMemory(object):

    def __init__(self,simstate,initialized,name):
        self.simstate = simstate
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

    def set(self,iaddr,address,srcval):
        if srcval.is_byte():
            self.set_byte(iaddr,address,srcval)
        elif srcval.is_word():
            self.set_byte(iaddr,address,srcval.get_low_byte())
            self.set_byte(iaddr,address+1,srcval.get_high_byte())
        elif srcval.is_doubleword():
            self.set_byte(iaddr,address,srcval.get_low_byte())
            self.set_byte(iaddr,address+1,srcval.get_snd_byte())
            self.set_byte(iaddr,address+2,srcval.get_third_byte())
            self.set_byte(iaddr,address+3,srcval.get_high_byte())
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
                                           self.name + ' memory location at ' + str(address)
                                           + ' not initialized')

    def get(self,iaddr,address,size):
        if size == 1:
            return self.get_byte(iaddr,address)
        elif size == 2:
            b1 = self.get_byte(iaddr,address)
            b2 = self.get_byte(iaddr,address+1)
            return SV.compose_simvalue([b1, b2])
        elif size == 4:
            b1 = self.get_byte(iaddr,address)
            b2 = self.get_byte(iaddr,address+1)
            b3 = self.get_byte(iaddr,address+2)
            b4 = self.get_byte(iaddr,address+3)
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
                    lines.append(str(hex(a)).rjust(12) + '  ' + str(self.get(0,a,4)))
                except:
                    lines.append(str(hex(a)).rjust(12) + '  ?')
        return '\n'.join(lines)


class SimGlobalMemory(SimMemory):

    def __init__(self,simstate):
        SimMemory.__init__(self,simstate,True,'global')



class SimStackMemory(SimMemory):
    
    def __init__(self,simstate):
        SimMemory.__init__(self,simstate,False,'stack')
        

