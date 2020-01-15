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

class X86SubBorrow(X.X86OpcodeBase):

    # tags: [ 'sbb' ]
    # args: [ dst-op, src-op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_dst_operand(self): return self.x86d.get_operand(self.args[0])

    def get_src_operand(self): return self.x86d.get_operand(self.args[1])

    def get_operands(self):
        return [ self.get_dst_operand(), self.get_src_operand() ]

    # xdata: [ "a:vxxxxxx" ; lhs, rhs1, rhs2, rhs1-rhs2, rhs1-rhs2-simplified,
    #                        rhs1-rhs2+1, rhs1-rhs2+1-simplified ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 7:
            lhs = str(xprs[0])
            rhsx = str(xprs[3])
            rrhsx = str(xprs[4])
            rhsx = X.simplify_result(xargs[3],xargs[4],rhsx,rrhsx)
            rhsx1 = str(xprs[5])
            rrhsx1 = str(xprs[6])
            rhsx1 = X.simplify_result(xargs[5],xargs[6],rhsx1,rrhsx1)
            return (lhs + ' = ' + rhsx + ' or ' + rhsx1)
        else:
            return self.tags[0] + ':????'

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 7: return [ xprs[0] ]
        else: return []

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 7: return [ xprs[6] ]
        else: return []

    # --------------------------------------------------------------------------
    # Adds the source operand (second operand) and the carry (CF) flag, and
    # subtracts the result from the destination operand (first operand). The
    # result of the subtraction is stored in the destination operand.
    # When an immediate value is used as an operand, it is sign-extended to the
    # length of the destination operand format.
    # The SBB instruction does not distinguish between signed or unsigned
    # operands. Instead, the processor evaluates the result for both data types
    # and sets the OF and CF flags to indicate a borrow in the signed or
    # unsigned result, respectively. The SF flag indicates the sign of the
    # signed result.
    #
    # Flags affected:
    # The OF, SF, ZF, AF, PF, and CF flags are set according to the result.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        dstop = self.get_dst_operand()
        size = dstop.get_size()
        srcval = simstate.get_rhs(iaddr,srcop)
        srcval = srcval.sign_extend(size)
        dstval = simstate.get_rhs(iaddr,dstop)
        cflag = simstate.get_flag_value('CF')
        if cflag is None:
            result = SV.simundefined
            simstate.set(iaddr,dstop,SV.simundefined)
        else:
            cflagval = SV.mk_simvalue(size,cflag)
            srcval = srcval.add(cflagval)
            result = dstval.sub(srcval)
            simstate.set(iaddr,dstop,result)
            simstate.update_flag('CF',dstval.sub_carries(srcval))
            simstate.update_flag('OF',dstval.sub_overflows(srcval))
            simstate.update_flag('SF',result.is_negative())
            simstate.update_flag('ZF',result.is_zero())
            simstate.update_flag('PF',result.is_odd_parity())
