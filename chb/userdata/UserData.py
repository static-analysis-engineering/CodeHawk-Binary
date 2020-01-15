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

from chb.userdata.UserXorEncoding import UserXorEncoding
from chb.userdata.UserCallTarget import UserCallTarget
from chb.userdata.UserCfNop import UserCfNop
from chb.userdata.UserStackAdjustment import UserStackAdjustment
from chb.userdata.UserFunctionNames import UserFunctionNames
from chb.userdata.SymbolicAddresses import SymbolicAddresses

class UserData(object):

    def __init__(self,app,xnode):
        self.app = app
        self.xnode = xnode
        self.symbolicaddresses = None   # SymbolicAddresses
        self.functionnames = None       # UserFunctionNames
        self.get_symbolic_addresses()
        self.get_function_names()

    def get_symbolic_addresses(self):
        if self.symbolicaddresses is None:
            xsymaddresses = self.xnode.find('symbolic-addresses')
            if not xsymaddresses is None:
                self.symbolicaddresses = SymbolicAddresses(self,xsymaddresses)
        return self.symbolicaddresses

    def has_symbolic_address(self,addr):
        if self.symbolicaddresses is None:
            return False
        return self.symbolicaddresses.has_symbolic_address(addr)

    def get_function_names(self):
        if self.functionnames is None:
            xfunctionnames = self.xnode.find('function-names')
            if not xfunctionnames is None:
                self.functionnames = UserFunctionNames(self,xfunctionnames)
        return self.functionnames

    def get_call_targets(self):
        calltargets = self.xnode.find('call-targets')
        if not calltargets is None:
            return [ UserCallTarget(self,x) for x in calltargets.findall('tgt') ]
        return []

    def get_xor_encodings(self):
        encodings = self.xnode.find('encodings')
        if not encodings is None:
            return [ UserXorEncoding(self,x) for x in encodings.findall('encoding') ]
        return []

    def get_cfnops(self):
        cfnops = self.xnode.find('cfnops')
        if not cfnops is None:
            return [ UserCfNop(self,x) for x in cfnops.findall('nop') ]
        return []

    def get_stack_adjustments(self):
        adjs = self.xnode.find('esp-adjustments')
        if not adjs is None:
            return [ UserStackAdjustment(self,x) for x in adjs.findall('esp-adj') ]
        return []

    def get_cfnop_summary(self):
        cfnops = self.get_cfnops()
        if not cfnops is None:
            result = {}
            for nop in cfnops:
                desc = nop.getdesc()
                if not desc in result: result[desc] = 0
                result[desc] += 1
            return result

    def __str__(self):
        lines = []
        calltargets = self.get_call_targets()
        xorencodings = self.get_xor_encodings()
        cfnops =  self.get_cfnops()
        stackadjustments = self.get_stack_adjustments()
        if len(calltargets) > 0:
            lines.append('Call targets')
            for c in calltargets:
                lines.append('  ' + str(c))
        if len(xorencodings) > 0:
            lines.append('Xor encodings')
            for x in xorencodings:
                lines.append('  ' + str(x))
        if len(cfnops) > 0:
            lines.append('Control flow nops')
            for c in cfnops:
                lines.append('  ' + str(c))
        if len(stackadjustments) > 0:
            for s in stackadjustments:
                lines.append('  ' + str(s))
        return '\n'.join(lines)

