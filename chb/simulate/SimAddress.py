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
import chb.simulate.SimUtil as SU
import chb.simulate.SimValue as SV

class SimAddress(SV.SimDoubleWordValue):

    def __init__(self,base,offset,undefined=False):
        SV.SimDoubleWordValue.__init__(self,offset,undefined)
        self.base = base         # 'global', 'stack', baseaddress

    def is_address(self): return True

    def is_aligned(self,size=4): return (self.value % size) == 0

    def is_global_address(self): return False
    def is_stack_address(self): return False
    def is_return_address(self): return False

    def to_hex(self): return hex(self.value)

    def __str__(self): return self.base + ':' + str(self.to_hex())


class SimGlobalAddress(SimAddress):

    def __init__(self,address,undefined=False):
        SimAddress.__init__(self,'global',address,undefined)

    def is_global_address(self): return True

    def add_offset(self,offset):
        newoffset = self.value + offset
        return SimGlobalAddress(newoffset,self.undefined)

    def add(self,other): return self.add_offset(other.to_signed_int())

    def sub(self,other): return self.add_offset(-other.to_signed_int())

    def __str__(self): return str(self.to_hex())


class SimStackAddress(SimAddress):

    def __init__(self,offset,undefined=False):
        SimAddress.__init__(self,'stack',offset,undefined)

    def add_offset(self,offset):
        newoffset = self.get_offset() + offset
        return SimStackAddress(newoffset,self.undefined)

    def add(self,other): return self.add_offset(other.to_signed_int())

    def sub(self,other): return self.add_offset(-other.to_signed_int())

    def is_stack_address(self): return True

    def __str__(self): return str('stack:' + str(self.to_signed_int()))


class SimReturnAddress(SimAddress):

    def __init__(self):
        SimAddress.__init__(self,'return',0,True)

    def is_return_address(self): return True

    def __str__(self): return 'return-address'
