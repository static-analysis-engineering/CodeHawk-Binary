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

class X86Xchg(X.X86OpcodeBase):

    # tags: [ 'xchg' ]
    # args: [ op1, op2 ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_op1(self): return self.x86d.get_operand(self.args[0])

    def get_op2(self): return self.x86d.get_operand(self.args[1])

    def get_operands(self):
        return  [ self.get_op1(), self.get_op2() ]

    # xdata: [ "nop" ] lhs and rhs are the same
    #        [ "a:vvxx" ],[ lhs1, lhs2, rhs1, rhs2 ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xtags) == 1 and xtags[0] == 'nop':
            return 'nop'
        elif len(xprs) == 4:
            lhs1 = str(xprs[0])
            lhs2 = str(xprs[1])
            rhs1 = str(xprs[2])
            rhs2 = str(xprs[3])
            return (lhs1 + ' = ' + rhs2 + '; ' + lhs2 + ' = ' + rhs1)
        else:
            return 'xchg:????'

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 4: return [ xprs[0], xprs[1] ]
        else: return []

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 4: return [ xprs[2], xprs[3] ]
        else: return []

    # --------------------------------------------------------------------------
    # Exchanges the contents of the destination (first) and source (second)
    # operands.
    #
    # Flags affected: None
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        op1 = self.get_op1()
        op2 = self.get_op2()
        val1 = simstate.get_rhs(iaddr,op1)
        val2 = simstate.get_rhs(iaddr,op2)
        simstate.set(iaddr,op1,val2)
        simstate.set(iaddr,op2,val1)
