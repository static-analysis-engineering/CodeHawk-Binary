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

class X86IMul(X.X86OpcodeBase):

    # tags: [ 'imul' ]
    # args: [ size, dst-op, src1-op, src2-op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_size(self): return int(self.args[0])

    def get_dst_operand(self): return self.x86d.get_operand(self.args[1])

    def get_src1_operand(self): return self.x86d.get_operand(self.args[2])

    def get_src2_operand(self): return self.x86d.get_operand(self.args[3])

    def get_operands(self):
        return  [ self.get_dst_operand(), self.get_src1_operand(),
                      self.get_src2_operand() ]

    # xdata: [ "a:vxxxx": lhs, rhs1, rhs2, product, product-simplified ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        lhs = str(xprs[0])
        rhs = str(xprs[3])
        rrhs = str(xprs[4])
        rhs = X.simplify_result(xargs[3],xargs[4],rhs,rrhs)
        return lhs + ' = ' + rhs

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[0] ]

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        return [ xprs[4] ]

    # --------------------------------------------------------------------------
    # Performs a signed multiplication of two operands. When an immediate value
    # is used as an operand, it is sign-extended to the length of the destination
    # operand format. The result is truncated to the length of the destination
    # before it is stored in the destination register.
    #
    # The CF and OF flags are set when significant bit (including the sign bit)
    # are carried into the upper half of the result. The CF and OF flags are
    # cleared when the result (including the sign bit) fits exactly in the lower
    # half of the result.
    #
    # Flags affected:
    # For the one operand form of the instruction, the CF and OF flags are set
    # when signif- icant bits are carried into the upper half of the result and
    # cleared when the result fits exactly in the lower half of the result. For
    # the two- and three-operand forms of the instruction, the CF and OF flags
    # are set when the result must be truncated to fit in the destination operand
    # size and cleared when the result fits exactly in the destination operand
    # size. The SF, ZF, AF, and PF flags are undefined.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        src1op = self.get_src1_operand()
        src2op = self.get_src2_operand()
        dstop = self.get_dst_operand()
        src1val = simstate.get_rhs(iaddr,src1op)
        src2val = simstate.get_rhs(iaddr,src2op).sign_extend(self.get_size())
        result = src1val.mul(src2val)
        lowresult = result.get_low_half()
        highresult = result.get_high_half()
        if dstop.get_size() < result.get_width() / 8:
            simstate.set(iaddr,dstop,lowresult)
        else:
            simstate.set(iaddr,dstop,result)
        simstate.update_flag('CF',not highresult.is_zero())
        simstate.update_flag('OF',not highresult.is_zero())
        simstate.undefine_flag('SF')
        simstate.undefine_flag('ZF')
        simstate.undefine_flag('PF')
        
