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


class X86ShiftRightDouble(X.X86OpcodeBase):

    # tags: [ 'shrd' ]
    # args: [ dst-op, src-op, shift ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_dst_operand(self): return self.x86d.get_operand(self.args[0])

    def get_src_operand(self): return self.x86d.get_operand(self.args[1])

    def get_shift_operand(self): return self.x86d.get_operand(self.args[2])

    def get_operands(self):
        return  [ self.get_dst_operand(), self.get_src_operand(),
                      self.get_shift_operand() ]

    # xdata: [ "a:vxxxxx": lhs, dstrhs, dstrhs-rewrittten, srcrhs, srcrhs-rewritten, shift ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 6:
            lhs = str(xprs[0])
            dstrhs = str(xprs[1])
            rdstrhs = str(xprs[2])
            srcrhs = str(xprs[3])
            rsrcrhs = str(xprs[4])
            shift = str(xprs[5])
            return (lhs + ' = ' + rdstrhs + ' shift in right ' + rsrcrhs + ' by ' + shift + ' bits')
        else:
            return 'pending:shrd'

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 6: return [ xprs[0] ]
        else: return []

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 6: return [ xprs[4] ]
        else: return []

    # --------------------------------------------------------------------------
    # The instruction shifts the first operand (destination operand) to the
    # right the number of bits specified by the third operand (count operand).
    # The second operand (source operand) provides bits to shift in from the
    # left (starting with the most significant bit of the destination operand).
    #
    # The count operand is an unsigned integer that can be stored in an
    # immediate byte or the CL register. If the count operand is CL, the shift
    # count is the logical AND of CL and a count mask. Ihe width of the count
    # mask is 5 bits. Only bits 0 through 4 of the count register are used
    # (masking the count to a value between 0 and 31). If the count is greater
    # than the operand size, the result is undefined.
    #
    # If the count is 1 or greater, the CF flag is filled with the last bit
    # shifted out of the destination operand. For a 1-bit shift, the OF
    # flag is set if a sign change occurred; otherwise, it is cleared. If
    # the count operand is 0, flags are not affected.
    #
    # Flags affected:
    # If the count is 1 or greater, the CF flag is filled with the last bit
    # shifted out of the destination operand and the SF, ZF, and PF flags are
    # set according to the value of the result. For a 1-bit shift, the OF flag
    # is set if a sign change occurred; otherwise, it is cleared. For shifts
    # greater than 1 bit, the OF flag is undefined. If a shift occurs, the AF
    # flag is undefined. If the count operand is 0, the flags are not affected.
    # If the count is greater than the operand size, the flags are undefined.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        shiftop = self.get_shift_operand()
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        shiftval = simstate.get_rhs(iaddr,shiftop)
        dstval = simstate.get_rhs(iaddr,dstop)
        (cflag,result) = dstval.bitwise_shrd(srcval,shiftval)
        simstate.set(iaddr,dstop,result)
        if shiftval.value > 0:
            if shiftval.value == 1:
                msbd = dstval.get_msb()
                msbr = result.get_mwb()
                if msbd == msbr:
                    simstate.clear_flag('OF')
                else:
                    simstate.set_flag('OF')
            else:
                simstate.undefine_flag('OF')
            simstate.update_flag('CF',cflag)
            simstate.update_flag('SF',result.is_negative())
            simstate.update_flag('ZF',result.is_zero())
            simstate.update_flag('PF',result.is_odd_parity())
            
