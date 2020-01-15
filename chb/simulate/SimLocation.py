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


class SimLocation(object):

    def __init__(self): pass

    def is_register(self): return False
    def is_double_register(self): return False
    def is_memory_location(self): return False
    def is_global(self): return False
    def is_aligned(self): return False

    def __str__(self): return 'location'

class SimRegister(SimLocation):

    def __init__(self,reg):
        self.reg = reg

    def is_register(self): return True

    def __str__(self): return reg


class SimDoubleRegister(SimLocation):

    def __init__(self,reglow,reghigh):
        self.reglow = reglow
        self.reghigh = reghigh

    def is_double_register(self): return True

    def __str__(self): return reglow + ':' + reghigh


class SimMemoryLocation(SimLocation):

    def __init__(self,address):
        self.address = address

    def is_memory_location(self): return True

    def is_aligned(self): return self.address.is_aligned()

    def is_global(self): return self.address.is_global_address()

    def is_stack(self): return self.address.is_stack_address()

    def get_offset(self):
        if self.is_stack(): return self.address.get_offset()
        raise UF.CHBError('Location is not a stack location: ' + str(self))

    def get_address(self):
        if self.is_global(): return self.address.to_unsigned_int()

    def __str__(self):  return str(self.address)
        

