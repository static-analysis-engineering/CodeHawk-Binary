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

import chb.elfformat.ELFHeader as EH
import chb.simulate.SimMemory as M
import chb.simulate.SimSymbolicValue as SSV
import chb.simulate.SimValue as SV
import chb.simulate.SimUtil as SU


class MIPSimStackMemory(M.SimMemory):

    def __init__(self,simstate,initialized,stackvalues=None,stackvaluesstart=0):
        M.SimMemory.__init__(self,simstate,initialized,'stack')
        self.stackvalues = stackvalues
        self.stackvaluesstart = stackvaluesstart
        self._initialize()

    def set_environment_string(self,iaddr): pass

    def _initialize(self):
        if self.stackvalues:
            for i in range(0,len(self.stackvalues),2):
                b = int(self.stackvalues[i:i+2],16)
                offset = (i//2) + self.stackvaluesstart
                self.set_byte(0,offset,SV.SimByteValue(b))

class MIPSimGlobalMemory(M.SimMemory):

    def __init__(self,simstate,app,initialized=False):
        M.SimMemory.__init__(self,simstate,initialized,'global')
        self.bigendian = self.simstate.bigendian
        self.app = app
        self.accesses = {}

    def get(self,iaddr,address,size): return self.get_from_section(iaddr,address,size)

    def get_from_section(self,iaddr,address,size):
        if address.is_defined():
            elfheader = self.app.get_elf_header()
            sectionindex = elfheader.get_elf_section_index(address.get_offset_value())
            if sectionindex is None:
                memval = SV.mk_simvalue(0,size=size)
                self.simstate.add_logmsg('global memory', str(address) + ' uninitialized')
                return memval
        offset = address.get_offset_value()
        for i in range(offset,offset+size):
            byteval = self.app.get_elf_header().get_memory_value(i,sectionindex)
            self.set_byte(iaddr,i,SV.SimByteValue(byteval))
        memval = M.SimMemory.get(self,iaddr,address,size,bigendian=self.bigendian)
        if not memval.is_defined():
            memval = mk_simvalue(0,size=size)
            self.simstate.add_logmsg('global memory', str(address) + ' uninitialized')
        self.accesses.setdefault(str(address),[])
        self.accesses[str(address)].append(str(iaddr) + ':' + str(memval))
        return memval


class MIPSimBaseMemory(M.SimMemory):

    def __init__(self,simstate,base,initialized=False,buffersize=None):
        M.SimMemory.__init__(self,simstate,initialized,base)
        self.bigendian = self.simstate.bigendian
        self.buffersize = buffersize
        self.status = 'valid'

    def free(self): self.status = 'freed'

    def is_valid(self): return self.status == 'valid'

    def get_buffersize(self): return self.buffersize

    def has_buffersize(self): return not self.buffersize is None

    def get(self,iaddr,address,size,bigendian=False):
        try:
            memval = M.SimMemory.get(self,iaddr,address,size,bigendian=self.bigendian)
        except SU.CHBSimError:
            name = self.name + '[' + str(address.get_offset()) + ']'
            return SSV.SimSymbol(name)
        else:
            return memval
