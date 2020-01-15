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

class X86Push(X.X86OpcodeBase):

    # tags: [ 'push' ]
    # args: [ size, src-op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_size(self): return int(self.args[0])

    def get_src_operand(self): return self.x86d.get_operand(self.args[1])

    def get_operands(self): return [ self.get_src_operand() ]

    def get_opcode_operations(self):
        src = self.get_src_operand()
        dec = 'esp = esp-4'
        mem = 'mem[esp] = ' + src.to_operand_string()
        return [ dec , mem ]

    # xdata: [ "a:x"; "arg" ; callsite ],[ x, x, argindex ] function argument
    #        [ "a:v", "save" ] save initial value of register to the stack
    #        [ "a:vx" ] push operand to the stack
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xtags) == 0:
            if len(xprs) > 0:
                return str(xprs[0]) + " := " + str(xprs[1])
            else:
                return 'arg to ???'
        elif len(xtags) == 1 and (xtags[0] == 'save'):
            return 'save ' + str(xprs[0])
        elif len(xtags) == 2 and (xtags[0] == 'arg'):
            callsite = xtags[1]
            argindex = xargs[2]
            xval = str(xprs[1])
            return '[' + str(callsite) + ':' + str(argindex) + ': ' + xval + ']'
        else:
            return self.tags[0]

    def get_operand_values(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xtags) == 0 and len(xprs) > 0:
            return [ xprs[1] ]
        elif (len(xtags) == 1) and (xtags[0] == 'arg'):
            return [ xprs[1] ]
        else:
            return []

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if ((len(xtags) == 1 and (xtags[0]   == 'arg'))
                or (len(xtags) == 0 and len(xprs) > 1)):
            return [ xprs[1] ]
        else:
            return []


    # --------------------------------------------------------------------------
    # Decrements the stack pointer and then stores the source operand on the top
    # of the stack. if the address-size and operand-size attributes are 32, the
    # 32-bit ESP register (stack pointer) is decremented by 4. If both attributes
    # are 16, the 16-bit SP register (stack pointer) is decremented by 2.
    # If the source operand is an immediate and its size is less than the address
    # size of the stack, a sign-extended value is pushed on the stack. If the
    # source operand is the FS or GS and its size is less than the address size
    # of the stack, the zero-extended value is pushed on the stack.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcval = simstate.get_rhs(iaddr,self.get_src_operand())
        simstate.push_value(iaddr,srcval.to_doubleword(signextend=True))
