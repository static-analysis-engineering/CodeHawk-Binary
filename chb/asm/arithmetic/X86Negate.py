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

class X86Negate(X.X86OpcodeBase):

    # tags: [ 'neg' ]
    # args: [ op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_operand(self): return self.x86d.get_operand(self.args[0])

    def get_operands(self): return [ self.get_operand() ]

    # xdata: [ "a:vxxx" ],[ lhs, rhs, rhs-operation, rhs-operation-simplified ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhsx = str(xprs[2])
        rrhsx = str(xprs[3])
        rhs = X.simplify_result(xargs[2],xargs[3],rhsx,rrhsx)
        return lhs + ' = ' + rhs

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[3] ]

    # --------------------------------------------------------------------------
    # Replaces the value of operand (the destination operand) with its two's
    # complement. (This operation is equivalent to subtracting the operand from
    # 0.)
    #
    # Flags affected:
    # The CF flag set to 0 if the source operand is 0; otherwise it is set to 1.
    # The OF, SF, ZF, AF, and PF flags are set according to the result.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        op = self.get_operand()
        srcval = simstate.get_rhs(iaddr,op)
        zero = SV.mk_simvalue(op.get_size(),0)
        result = zero.sub(srcval)
        simstate.set(iaddr,op,result)
        if srcval.is_zero():
            simstate.set_flag('CF')
        else:
            simstate.clear_flag('CF')
        simstate.update_flag('OF',zero.sub_overflows(srcval))
        simstate.update_flag('SF',result.is_negative())
        simstate.update_flag('ZF',result.is_zero())
        simstate.update_flag('PF',result.is_odd_parity())
        
