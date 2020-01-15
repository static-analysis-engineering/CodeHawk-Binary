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

class SymbolicAddress(object):

    def __init__(self,xnode):
        self.xnode = xnode
        self.addr = self.xnode.get('a')
        self.name = self.xnode.get('name')
        self.size = int(self.xnode.get('size'))

class SymbolicAddresses(object):

    def __init__(self,user,xnode):
        self.user = user
        self.xnode = xnode
        self.addresses = {} 
        self._initialize()

    def has_symbolic_address(self,addr): return addr in self.addresses

    def get_symbolic_address_name(self,addr):
        if addr in self.addresses:
            return self.addresses[addr].name
        return addr

    def _initialize(self):
        symaddresses =  [ SymbolicAddress(x) for x in self.xnode.findall('syma') ]
        for a in symaddresses:
            self.addresses[a.addr] = a

        
