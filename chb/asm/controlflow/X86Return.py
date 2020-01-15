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

import chb.asm.X86OpcodeBase as X
import chb.simulate.SimulationState as S
import chb.simulate.SimUtil as SU
import chb.simulate.SimValue as SV

class X86Return(X.X86OpcodeBase):

    # tags: [ 'ret' ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def is_return(self): return True
    def has_return_expr(self): return len(self.args) > 1

    def get_return_expr(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xargs) > 1:
            return xprs[1]

    def get_operands(self): return []

    # xdata: [ "a:xx" ],[ eax, eax-rewritten, bytes popped ] if bytes are popped from the stack
    #        [ "a:xx" ],[ eax, eax-rewritten ] if no bytes are popped from the stack
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xargs) == 2:
            eax = str(xprs[0])
            reax = str(xprs[1])
            eax = X.simplify_result(xargs[0],xargs[1],eax,reax)
            return 'return (' + eax + ')'
        elif len(xargs) == 3:
            eax = str(xprs[0])
            reax = str(xprs[1])
            eax = X.simplify_result(xargs[0],xargs[1],eax,reax)
            popped = str(xargs[2])
            return 'return (' + eax + ') (adj: ' + popped + ')'
        else:
            return 'ret:????'

    def simulatex(self,iaddr,simstate): raise SU.KTSimFunctionReturn(iaddr)
