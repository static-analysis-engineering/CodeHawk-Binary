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

class X86Sub(X.X86OpcodeBase):

    # tags: [ 'sub' ]
    # args: [ dst-op, src-op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_dst_operand(self): return self.x86d.get_operand(self.args[0])

    def get_src_operand(self): return self.x86d.get_operand(self.args[1])

    def get_operands(self):
        return [ self.get_dst_operand(), self.get_src_operand() ]

    def get_opcode_operations(self):
        src = self.get_src_operand().to_operand_string()
        dst = self.get_dst_operand().to_operand_string()
        return [ dst + ' = ' + dst + ' - ' + src ]

    # xdata: [ "a:vxxxx": lhs, rhs1, rhs2, sum, sum-simplified ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 5:
            lhs = str(xprs[0])
            rdiff = xprs[3]
            rrdiff = xprs[4]
            rdiff = X.simplify_result(xargs[3],xargs[4],rdiff,rrdiff)
            return lhs + ' := ' + rdiff
        else:
            return 'sub:????'

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 5:
            return [ xprs[0] ]
        else:
            return []

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 5:
            return [ xprs[4] ]
        else:
            return []

    # --------------------------------------------------------------------------
    # Subtracts the second operand (source operand) from the first operand
    # (destination operand) and stores the result in the destination operand.
    # The SUB instruction performs integer subtraction. It evaluates the result
    # for both signed and unsigned integer operands and sets the OF and CF flags
    # to indicate an overflow in the signed or unsigned result, respectively.
    # The SF flag indicates the sign of the signed result.
    #
    # Flags affected:
    # The OF, SF, ZF, AF, PF, and CF flags are set according to the result.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        dstval = simstate.get_rhs(iaddr,dstop)
        result = dstval.sub(srcval)
        simstate.set(iaddr,dstop,result)
        simstate.update_flag('CF',dstval.sub_carries(srcval))
        simstate.update_flag('OF',dstval.sub_overflows(srcval))
        simstate.update_flag('SF',result.is_negative())
        simstate.update_flag('ZF',result.is_zero())
        simstate.update_flag('PF',result.is_odd_parity())
