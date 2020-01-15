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

class X86ShiftARight(X.X86OpcodeBase):

    # tags: [ 'sar' ]
    # args: [ dst-op, src-op ]
    def __init__(self,x86d,index,tags,args):
        X.X86OpcodeBase.__init__(self,x86d,index,tags,args)

    def get_dst_operand(self): return self.x86d.get_operand(self.args[0])

    def get_src_operand(self): return self.x86d.get_operand(self.args[1])

    def get_operands(self):
        return [ self.get_dst_operand(), self.get_src_operand() ]

    # xdata: [ "a:vdddd": lhs, rhsbase, rhs-expr, rhs-result, rhs-result-simplified ]
    def get_annotation(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 5:
            lhs = str(xprs[0])
            rhs = str(xprs[3])
            rrhs = str(xprs[4])
            rrhs = X.simplify_result(xargs[3],xargs[4],rhs,rrhs)
            return lhs + ' = ' + rrhs
        else:
            return (self.tags[0] + ':????')

    def get_lhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 5: return [ xprs[0] ]
        else: return []

    def get_rhs(self,xdata):
        (xtags,xargs,xprs) = xdata.get_xprdata()
        if len(xprs) == 5: return [ xprs[4] ]
        else: return []

    # --------------------------------------------------------------------------
    # Shifts the bits in the first operand (destination operand) to the right by
    # the number of bits specified in the second operand (count operand). Bits
    # shifted beyond the destination operand boundary are first shifted into the
    # CF flag, then discarded. At the end of the shift operation, the CF flag
    # contains the last bit shifted out of the destination operand.
    #
    # The count operand can be an immediate value or the CL register. The count
    # is masked to 5 bits. The count range is limited to 0 to 31.
    #
    # The shift arithmetic right (SAR) instruction shifts the bits of the
    # destination operand to the right (toward less significant bit locations).
    # For each shift count, the least significant bit of the destination operand
    # is shifted into the CF flag, and the most significant bit is either set or
    # cleared. The SAR instruction sets or
    # clears the most significant bit to correspond to the sign (most
    # significant bit) of the original value in the destination operand. In
    # effect, the SAR instruction fills the empty bit position's shifted value
    # with the sign of the unshifted value.
    #
    # The OF flag is affected only on 1-bit shifts. For the SAR instruction, the
    # OF flag is cleared for all 1-bit shifts.
    #
    # Flags affected:
    # The CF flag contains the value of the last bit shifted out of the destination
    # operand. The OF flag is affected only on 1-bit shifts; otherwise, it is
    # undefined.. The SF, ZF, and PF flags are set according to the result.
    # --------------------------------------------------------------------------
    def simulate(self,iaddr,simstate):
        srcop = self.get_src_operand()
        dstop = self.get_dst_operand()
        srcval = simstate.get_rhs(iaddr,srcop)
        dstval = simstate.get_rhs(iaddr,dstop)
        (cflag,result) = dstval.bitwise_sar(srcval)
        simstate.set(iaddr,dstop,result)
        if srcval.value > 0:
            simstate.update_flag('CF',cflag)
            if srcval.value == 1:
                simstate.clear_flag('OF')
            else:
                simstate.undefine_flag('OF')
            simstate.update_flag('SF',result.is_negative())
            simstate.update_flag('ZF',result.is_zero())
            simstate.update_flag('PF',result.is_odd_parity())
        
