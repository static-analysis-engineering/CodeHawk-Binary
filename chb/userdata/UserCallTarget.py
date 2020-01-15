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

class UserCallTarget():

    def __init__(self,iuser,xnode):
        self.iuser = iuser
        self.xnode = xnode
        self.faddr = self.xnode.get('fa')
        self.iaddr = self.xnode.get('ia')
        self.dll = self.xnode.get('dll')
        self.name = self.xnode.get('name')
        self.appaddr = self.xnode.get('appa')
        self.ctag = self.xnode.get('ctag')

    def is_dll_tgt(self): return (self.ctag == 'dll')

    def is_app_tgt(self): return (self.ctag == 'app')

    def __str__(self):
        addr = self.faddr.ljust(10) + self.iaddr.ljust(10)
        if self.isdlltgt():
            tgt = self.dll + ':' + self.name
        else:
            tgt = self.appaddr
        return (addr + '  ' + tgt)
