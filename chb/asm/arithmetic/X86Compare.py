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


class X86Compare(X.X86OpcodeBase):

    # tags: [ 'cmp' ]
    # args: [ op1, op2 ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_operand_1(self): return self.x86d.get_operand(self.args[0])

    def get_operand_2(self): return self.x86d.get_operand(self.args[1])

    def get_operands(self):
        return [ self.get_operand_1(), self.get_operand_2() ]

    def get_annotation(self,xdata):
        return ''

    # --------------------------------------------------------------------------
    # Compares the first source operand with the second source operand and sets
    # the status flags in the EFLAGS register according to the results.
    # The comparison is performed by subtracting the second operand from the
    # first operand and then setting the status flags in the same manner as the
    # SUB instruction. When an immediate value is used as an operand, it is
    # sign-extended to the length of the first operand.
    #
    # Flags affected:
    # The CF, OF, SF, ZF, AF, and PF flags are set according to the result.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        op1 = self.get_operand_1()
        op2 = self.get_operand_2()
        val1 = simstate.get_rhs(iaddr,op1)
        val2 = simstate.get_rhs(iaddr,op2).sign_extend(op1.get_size())
        result = val1.sub(val2)
        simstate.update_flag('CF',val1.sub_carries(val2))
        simstate.update_flag('OF',val1.sub_overflows(val2))
        simstate.update_flag('SF',result.is_negative())
        simstate.update_flag('ZF',result.is_zero())
        simstate.update_flag('PF',result.is_odd_parity())
        
