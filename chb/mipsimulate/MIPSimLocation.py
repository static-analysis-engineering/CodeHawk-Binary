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

class MIPSimLocation(object):

    def __init__(self): pass

    def is_register(self): return False
    def is_memory_location(self): return False

    def __str__(self): return 'mips-location'

class MIPSimRegister(MIPSimLocation):

    def __init__(self,reg):
        self.reg = reg

    def is_register(self): return True

    def __str__(self): return self.reg

class MIPSimMemoryLocation(MIPSimLocation):

    def __init__(self,address):
        self.address = address  # SimAddress

    def is_memory_location(self): return True

    def is_stack_location(self): return self.address.is_stack_address()

    def is_global_location(self): return self.address.is_global_address()

    def is_base_location(self): return self.address.is_base_address()

    def get_address(self): return self.address

    def __str__(self):
        if self.is_stack_location():
            return 'stack[' + str(self.get_address().get_offset().to_signed_int()) + ']'
        elif self.is_global_location():
            return 'global[' + str(self.get_address().get_offset()) + ']'
        elif self.is_base_location():
            return self.address.get_base() + '[' + str(self.get_address().get_offset()) + ']'
        else:
            return str('loc@' + str(self.address))
