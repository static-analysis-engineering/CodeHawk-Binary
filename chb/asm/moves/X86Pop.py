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

class X86Pop(X.X86OpcodeBase):

    # tags: [ 'pop' ]
    # args: [ size, op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_size(self): return int(self.args[0])

    def get_dst_operand(self): return self.x86d.get_operand(self.args[1])

    def get_operands(self): return [ self.get_dst_operand() ]

    # xdata: [ "a:v", "restore" ]  restore initial value of register
    #        [ "a:vxxx" ],[ lhs, rhs, esp, resp ] pop top value of the stack into operand
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xtags) == 1:
            return 'restore ' + str(xprs[0])
        else:
            lhs = str(xprs[0])
            rhs = str(xprs[1])
            esp = str(xprs[2])
            resp = str(xprs[3])
            resp =  X.simplify_result(xargs[2],xargs[3],esp,resp)
            return lhs + ' = ' + rhs + '; esp = ' + resp

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 4: return [ xprs[3] ]
        else: return []

    # --------------------------------------------------------------------------
    # Loads the value from the top of the stack to the location specified with
    # the destination operand (or explicit opcode) and then increments the stack
    # pointer. The destination operand can be a general-purpose register,
    # memory location, or segment register.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcval = simstate.pop_value(iaddr)
        simstate.set(iaddr,self.get_dst_operand(),srcval)
