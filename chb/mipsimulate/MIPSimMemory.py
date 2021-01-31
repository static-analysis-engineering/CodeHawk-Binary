# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2020-2021 Henny Sipma
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
import chb.util.fileutil as UF


class MIPSimStackMemory(M.SimMemory):

    def __init__(self,simstate,initialized=False):
        M.SimMemory.__init__(self,simstate,initialized,'stack')

    def set_environment_string(self,iaddr): pass


class MIPSimGlobalMemory(M.SimMemory):

    def __init__(self,simstate,app,initialized=False):
        M.SimMemory.__init__(self,simstate,initialized,'global')
        self.app = app
        self.accesses = {}
        self.patched_globals = self.simstate.simsupport.get_patched_globals()

    def get(self,iaddr,address,size):
        try:
            result = M.SimMemory.get(self,iaddr,address,size)
            if result.is_defined():
                return result
            else:
                return self.get_from_section(iaddr,address,size)
        except SU.CHBSimError:
            return self.get_from_section(iaddr,address,size)

    def has_patched_global(self,address):
        return hex(address.get_offset_value()) in self.patched_globals

    def get_patched_global(self,address):
        if self.has_patched_global(address):
            hexval = self.patched_globals[hex(address.get_offset_value())]
            return SV.mk_simvalue(int(hexval,16))
        raise UF.CHBError('No patched global found for ' + str(address))

    def get_from_section(self,iaddr,address,size):
        if address.is_defined():
            if self.has_patched_global(address):
                return self.get_patched_global(address)
            elfheader = self.app.get_elf_header()
            sectionindex = elfheader.get_elf_section_index(address.get_offset_value())
            if sectionindex is None:
                memval = SV.mk_simvalue(0,size=size)
                self.simstate.add_logmsg('global memory', str(address) + ' uninitialized')
                return memval
            offset = address.get_offset_value()
            for i in range(offset,offset+size):
                byteval = self.app.get_elf_header().get_memory_value(i,sectionindex)
                if byteval is not None:
                    self.set_byte(iaddr,i,SV.SimByteValue(byteval))
                else:
                    raise UF.CHBError('No value found for ' + hex(i) + ' in section ' +
                                      str(sectionindex))
            memval = M.SimMemory.get(self,iaddr,address,size)
            if not memval.is_defined():
                memval = mk_simvalue(0,size=size)
                self.simstate.add_logmsg('global memory', str(address) + ' uninitialized')
            self.accesses.setdefault(str(address),[])
            chrrep = ' (' + chr(memval.value) + ')' if memval.value < 128 else ''
            self.accesses[str(address)].append(str(iaddr) + ':' + str(memval) + chrrep)
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
            memval = M.SimMemory.get(self,iaddr,address,size)
        except SU.CHBSimError as e:
            name = self.name + '[' + str(address.get_offset()) + ']' + ' (value not retrieved: ' + str(e) + ')'
            return SSV.SimSymbol(name)
        else:
            return memval
